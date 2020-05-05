package org.harry.security.util;

import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.*;
import iaik.security.ec.common.ECStandardizedParameterFactory;
import iaik.security.ec.provider.ECCelerate;
import iaik.security.provider.IAIK;
import iaik.x509.SimpleChainVerifier;
import iaik.x509.X509Certificate;
import iaik.x509.X509ExtensionException;
import iaik.x509.X509ExtensionInitException;
import iaik.x509.extensions.*;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.trustlist.TrustListLoader;
import org.harry.security.util.trustlist.TrustListManager;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;

/**
 * This is a class for generating valid certificate chains and add the
 * CA and issuer to the p12 store and to the trust-list
 * @author Harald Glab-Plhak
 *
 */
public class CertificateWizzard {
    private TrustListLoader loader = new TrustListLoader();
    private TrustListManager manager = null;
    private KeyPair ca_rsa;
    private KeyPair inter_rsa;
    private KeyPair ca_ec;
    private KeyPair inter_ec;
    private X509Certificate caRSA;
    private X509Certificate caEC;
    private X509Certificate intermediateRSA;
    private X509Certificate intermediateEC;

    private final SimpleChainVerifier verifier = new SimpleChainVerifier();
    private final ConfigReader.MainProperties properties;
    private KeyStore store = null;
    private KeyStore storeEC = null;

    public static String APP_DIR;

    public static String APP_DIR_TRUST;

    public static final String PROP_STORE_NAME = "application.p12";
    public static final String PROP_TRUST_NAME = "privateTrust.xml";
    static {
        String userDir = System.getProperty("user.home");
        userDir = userDir + "\\AppData\\Local\\MySigningApp";
        File dir = new File(userDir);
        if (!dir.exists()){
            dir.mkdirs();
        }
        File dirTrust = new File(userDir, "trustedLists");
        if (!dirTrust.exists()) {
            dirTrust.mkdirs();
        }
        APP_DIR_TRUST = dirTrust.getAbsolutePath();
        APP_DIR= userDir;
    }
    public CertificateWizzard(ConfigReader.MainProperties properties) {
        try {
            manager = loader.getManager(null);
        } catch (IOException e) {

        }
        this.properties = properties;
        store = KeyStoreTool.initStore("PKCS12", "geheim");
        storeEC = KeyStoreTool.initStore("PKCS12", "geheim");
        // for verifying the created certificates

    }

    public KeyStore getStore() {
        return store;
    }

    public KeyStore getStoreEC() {
        return storeEC;
    }

    public TrustListLoader getLoader() {
        return loader;
    }

    public void generateCA() {
        try {
            X509Certificate [] certChain = new X509Certificate[1];
        Name issuer = new Name();
        KeyUsage usage = certUsage();
        issuer.addRDN(ObjectID.country,
                properties.getCountry());
        issuer.addRDN(ObjectID.organization ,properties.getOrganization());
        issuer.addRDN(ObjectID.organizationalUnit ,properties.getUnit());

        Name subject = new Name();
        subject.addRDN(ObjectID.country, properties.getCountry());
        subject.addRDN(ObjectID.organization , properties.getOrganization());
        subject.addRDN(ObjectID.organizationalUnit ,properties.getUnit());
        issuer.addRDN(ObjectID.commonName ,properties.getCommonName() +"RSA" );
        ca_rsa = generateKeyPair("RSA", 2048);
        caRSA = createCertificate(issuer,
                ca_rsa.getPublic(),
                issuer,
                ca_rsa.getPrivate(),
                (AlgorithmID)AlgorithmID.sha256WithRSAEncryption.clone(),
                null,
                usage);
            caRSA.verify();
            // set the CA cert as trusted root
            verifier.addTrustedCertificate(caRSA);
            certChain[0] = caRSA;
            KeyStoreTool.addKey(store, ca_rsa.getPrivate(),
                    properties.getKeystorePass().toCharArray(),
                    certChain, UUID.randomUUID().toString() + "" +
                            "RSA");
            issuer.removeRDN(ObjectID.commonName);
            issuer.addRDN(ObjectID.commonName ,properties.getCommonName() +"_EC" );
            ca_ec = generateKeyPairECC(571);
            caEC = createCertificate(issuer,
                    ca_ec.getPublic(),
                    issuer,
                    ca_ec.getPrivate(),
                    (AlgorithmID)AlgorithmID.ecdsa.clone(),
                    null,
                    usage);
            caEC.verify();
            // set the CA cert as trusted root
            verifier.addTrustedCertificate(caEC);
            certChain[0] = caEC;
            KeyStoreTool.addKey(storeEC, ca_ec.getPrivate(),
                    properties.getKeystorePass().toCharArray(),
                    certChain, UUID.randomUUID().toString() + "_EC");

            List<Vector<String>> paths = manager.collectPaths();
            manager.addX509Cert(paths.get(0), caRSA);
            manager.addX509Cert(paths.get(0),caEC);
        } catch (Exception ex) {
            throw new IllegalStateException("certificate generation failed", ex);
        }
    }

    public void generateIntermediate() {
        try {
            X509Certificate [] certChain = new X509Certificate[2];
            KeyUsage usage = certUsage();
            SubjectKeyIdentifier subjectKeyID = (SubjectKeyIdentifier) caRSA.getExtension(SubjectKeyIdentifier.oid);
            Name issuer = new Name();
            issuer.addRDN(ObjectID.country,
                    properties.getCountry());
            issuer.addRDN(ObjectID.organization, properties.getOrganization());
            issuer.addRDN(ObjectID.organizationalUnit, properties.getUnit());

            Name subject = new Name();
            subject.addRDN(ObjectID.country, properties.getCountry());
            subject.addRDN(ObjectID.organization, properties.getOrganization());
            subject.addRDN(ObjectID.organizationalUnit, properties.getUnit());
            issuer.addRDN(ObjectID.commonName, properties.getCommonName() + "RSA");
            subject.addRDN(ObjectID.commonName ,properties.getCommonName() + "RSA_Inter");
            inter_rsa = generateKeyPair("RSA", 2048);
            intermediateRSA = createCertificate(subject,
                    inter_rsa.getPublic(),
                    issuer,
                    ca_rsa.getPrivate(),
                    (AlgorithmID) AlgorithmID.sha256WithRSAEncryption.clone(),
                    subjectKeyID.get(),
                    usage);
            certChain[0] = intermediateRSA;
            certChain[1] = caRSA;
            // and verify the chain
            verifier.verifyChain(certChain);
            KeyStoreTool.addKey(store, inter_rsa.getPrivate(),
                    properties.getKeystorePass().toCharArray(),
                    certChain, UUID.randomUUID().toString() + "IntermediateRSA");
            issuer.removeRDN(ObjectID.commonName);
            issuer.addRDN(ObjectID.commonName ,properties.getCommonName() + "_EC");
            subject.removeRDN(ObjectID.commonName);
            subject.addRDN(ObjectID.commonName ,properties.getCommonName() + "_EC_Inter");
            inter_ec = generateKeyPairECC( 571);
            intermediateEC = createCertificate(subject,
                    inter_ec.getPublic(),
                    issuer,
                    ca_ec.getPrivate(),
                    (AlgorithmID) AlgorithmID.ecdsa.clone(),
                    subjectKeyID.get(),
                    usage);
            certChain[0] = intermediateEC;
            certChain[1] = caEC;
            // and verify the chain
            verifier.verifyChain(certChain);
            KeyStoreTool.addKey(storeEC, inter_ec.getPrivate(),
                    properties.getKeystorePass().toCharArray(),
                    certChain, UUID.randomUUID().toString() + "IntermediateEC");

            List<Vector<String>> paths = manager.collectPaths();
            manager.addX509Cert(paths.get(0), intermediateRSA);
            manager.addX509Cert(paths.get(0),intermediateEC);
        } catch (Exception ex) {
            throw new IllegalStateException("certificate generation failed", ex);
        }
    }

    public void generateUser() {
        try {
            X509Certificate [] certChain = new X509Certificate[3];
            SubjectKeyIdentifier subjectKeyID = (SubjectKeyIdentifier) intermediateRSA.getExtension(SubjectKeyIdentifier.oid);
            Name issuer = new Name();
            issuer.addRDN(ObjectID.country,
                    properties.getCountry());
            issuer.addRDN(ObjectID.organization, properties.getOrganization());
            issuer.addRDN(ObjectID.organizationalUnit, properties.getUnit());

            Name subject = new Name();
            subject.addRDN(ObjectID.country, properties.getCountry());
            subject.addRDN(ObjectID.organization, properties.getOrganization());
            subject.addRDN(ObjectID.organizationalUnit, properties.getUnit());
            issuer.addRDN(ObjectID.commonName, properties.getCommonName() + "" +
                    "RSA_Inter");
            subject.addRDN(ObjectID.commonName ,properties.getCommonName() + "_RSA_User");
            KeyPair userKeys = generateKeyPair("RSA", 2048);
            KeyUsage usage = signUsage();
             X509Certificate userCert = createCertificate(subject,
                    userKeys.getPublic(),
                    issuer,
                    inter_rsa.getPrivate(),
                    (AlgorithmID) AlgorithmID.sha256WithRSAEncryption.clone(),
                    subjectKeyID.get(),
                    usage);
            certChain[0] = userCert;
            certChain[1] = intermediateRSA;
            certChain[2] = caRSA;
            // and verify the chain
            verifier.verifyChain(certChain);
            KeyStoreTool.addKey(store, userKeys.getPrivate(),
                    properties.getKeystorePass().toCharArray(),
                    certChain, UUID.randomUUID().toString() + "UserRSA");
            issuer.removeRDN(ObjectID.commonName);
            issuer.addRDN(ObjectID.commonName ,properties.getCommonName() + "_EC_Inter");
            subject.removeRDN(ObjectID.commonName);
            subject.addRDN(ObjectID.commonName ,properties.getCommonName() + "_EC_User");
            KeyPair userKeysEC = generateKeyPairECC(571);
            X509Certificate userCertEC = createCertificate(subject,
                    userKeysEC.getPublic(),
                    issuer,
                    inter_ec.getPrivate(),
                    (AlgorithmID) AlgorithmID.ecdsa.clone(),
                    subjectKeyID.get(), usage);
            certChain[0] = userCertEC;
            certChain[1] = intermediateEC;
            certChain[2] = caEC;
            // and verify the chain
            verifier.verifyChain(certChain);
            KeyStoreTool.addKey(storeEC, userKeysEC.getPrivate(),
                    properties.getKeystorePass().toCharArray(),
                    certChain, UUID.randomUUID().toString() + "UserEC");
        } catch (Exception ex) {
            throw new IllegalStateException("certificate generation failed", ex);
        }
    }

    /**
     * Creates a certificate from the given values.
     *
     *
     *
     * @param subject the subject of the certificate
     * @param publicKey the public key to include
     * @param issuer the issuer of the certificate
     * @param privateKey the private key for signing the certificate
     * @param algorithm the signature algorithm to use
     * @param keyID the key id for the AuthotityKeyIdentifier extension
     * @param keyUsage the usage extension for the certificate
     * @return the certificate just created
     */
    public static X509Certificate createCertificate(Name subject, PublicKey publicKey,
                                                    Name issuer, PrivateKey privateKey, AlgorithmID algorithm, byte[] keyID,
                                                    KeyUsage keyUsage) {

        // create a new certificate
        X509Certificate cert = new X509Certificate();

        try {
            // set the values
            cert.setSerialNumber(new BigInteger(20, new Random()));
            cert.setSubjectDN(new Name(subject.toASN1Object()));
            cert.setPublicKey(publicKey);
            cert.setIssuerDN(new Name(issuer.toASN1Object()));

            GregorianCalendar date = new GregorianCalendar();
            // not before now
            cert.setValidNotBefore(date.getTime());

            if (issuer.equals(subject)) {
                // CA certificate
                date.add(Calendar.YEAR, 6);
                BasicConstraints basicConstraints = new BasicConstraints(true);
                cert.addExtension(basicConstraints);
                cert.addExtension(keyUsage);
            } else {
                date.add(Calendar.YEAR, 5);
                cert.addExtension(keyUsage);
                AuthorityKeyIdentifier authID = new AuthorityKeyIdentifier();
                authID.setKeyIdentifier(keyID);
                cert.addExtension(authID);
                GeneralNames generalNames = new GeneralNames();
                generalNames.addName(new GeneralName(GeneralName.rfc822Name, "smimetest@harryglab.com"));
                SubjectAltName subjectAltName = new SubjectAltName(generalNames);
                cert.addExtension(subjectAltName);
                ExtendedKeyUsage extKeyUsage = new ExtendedKeyUsage();
                //add purposes
                extKeyUsage.addKeyPurposeID(ExtendedKeyUsage.ocspSigning);
                extKeyUsage.addKeyPurposeID(ExtendedKeyUsage.timeStamping);
                extKeyUsage.setCritical(true);
                cert.addExtension(extKeyUsage);
                cert.addExtension(keyUsage);
                setOCSPUrl(cert, "http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/ocsp");
            }
            String explicitText = "This certificate may be used for testing purposes only";
            PolicyQualifierInfo policyQualifier = new PolicyQualifierInfo(null, null, explicitText);
            PolicyInformation[] policyInformations =
                    { new PolicyInformation(new ObjectID("1.3.6.1.4.1.2706.2.2.4.1.1.1.1"),
                            new PolicyQualifierInfo[] { policyQualifier }) };
            CertificatePolicies certPolicies = new CertificatePolicies(policyInformations);

            SubjectKeyIdentifier subjectKeyID = new SubjectKeyIdentifier(cert.getPublicKey());
            cert.addExtension(subjectKeyID);

            cert.addExtension(certPolicies);
            cert.setValidNotAfter(date.getTime());
            // and sign the certificate
            cert.sign(algorithm ,privateKey);
        } catch (CertificateException ex) {
            throw new RuntimeException("Error creating the certificate: "+ex.getMessage());
        } catch (InvalidKeyException ex) {
            throw new RuntimeException("Error creating the certificate: "+ex.getMessage());
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("Error creating the certificate: "+ex.getMessage());
        } catch (X509ExtensionException ex) {
            throw new RuntimeException("Error adding extension: "+ex.getMessage());
        } catch (CodingException | MalformedURLException ex) {
            throw new RuntimeException("Error adding SubjectKeyIdentifier extension: "+ex.getMessage());
        }
        return cert;
    }

    /**
     * Generate a KeyPair using the specified algorithm with the given size.
     *
     * @param algorithm the algorithm to use
     * @param bits the length of the key (modulus) in bits
     * @return the KeyPair
     */
    public static KeyPair generateKeyPair(String algorithm, int bits)
            throws NoSuchAlgorithmException {

        KeyPairGenerator generator = null;
        try {
            generator = KeyPairGenerator.getInstance(algorithm, "IAIK");
        } catch (NoSuchProviderException ex) {
            throw new NoSuchAlgorithmException("Provider IAIK not found!");
        }
        generator.initialize(bits);
        KeyPair kp = generator.generateKeyPair();
        return kp;
    }



    public static void initThis() {
        File keystore = new File(APP_DIR, PROP_STORE_NAME);
        File keystoreEC = new File(APP_DIR, PROP_STORE_NAME + "_EC");
        File trustFile = new File(APP_DIR_TRUST, PROP_TRUST_NAME);
        if (!keystore.exists() && !trustFile.exists()) {
            ConfigReader.MainProperties properties = ConfigReader.loadStore();
            properties.setKeystorePass("geheim");
            CertificateWizzard wizzard = new CertificateWizzard(properties);
            wizzard.generateCA();
            wizzard.generateIntermediate();
            wizzard.generateUser();
            try {
                KeyStoreTool.storeKeyStore(wizzard.getStore(),
                        new FileOutputStream(keystore),
                        properties.getKeystorePass().toCharArray());
                KeyStoreTool.storeKeyStore(wizzard.getStoreEC(),
                        new FileOutputStream(keystoreEC),
                        properties.getKeystorePass().toCharArray());
                wizzard.getLoader().storeTrust(new FileOutputStream(trustFile));
            } catch(Exception ex) {
                throw new IllegalStateException("could not initialize", ex);
            }
        }
    }

    public static void generateThis() {

        ConfigReader.MainProperties properties = ConfigReader.loadStore();
        File keystore = new File(properties.getKeystorePath());
        File keystoreEC = new File(properties.getKeystorePath() + "_EC");
        properties.setKeystorePass("geheim");
        CertificateWizzard wizzard = new CertificateWizzard(properties);
        wizzard.generateCA();
        wizzard.generateIntermediate();
        wizzard.generateUser();
        try {
            KeyStoreTool.storeKeyStore(wizzard.getStore(),
                    new FileOutputStream(keystore),
                    properties.getKeystorePass().toCharArray());
            KeyStoreTool.storeKeyStore(wizzard.getStoreEC(),
                    new FileOutputStream(keystoreEC),
                    properties.getKeystorePass().toCharArray());
        } catch(Exception ex) {
            throw new IllegalStateException("could not initialize", ex);
        }

    }


    /**
     * Generates a key pair for a curve with a certain name
     *
     * @param bitlength
     *          the bitlength of the domain parameters to be used
     * @return the generated key pair
     */
    protected KeyPair generateKeyPairECC(final int bitlength) {
        try {
            final SecureRandom random = SecureRandom.getInstance("SHA512PRNG-SP80090", IAIK.getInstance());;
            final AlgorithmParameterSpec params = ECStandardizedParameterFactory
                    .getParametersByBitLength(bitlength);

            System.out.println();
            System.out.println("Using the following EC domain parameters: ");
            System.out.println(params);
            System.out.println();

            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", ECCelerate.getInstance());
            kpg.initialize(params, random);

            return kpg.generateKeyPair();
        } catch (final Exception e) {
            // should not occur SecureRandom.getInstance("SHA512PRNG-SP80090", IAIK.getInstance());
            e.printStackTrace();

            return null;
        }
    }

    public static KeyUsage certUsage() {
        return new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
    }

    public static KeyUsage signUsage() {
        return new KeyUsage(KeyUsage.digitalSignature |KeyUsage.cRLSign |
                KeyUsage.nonRepudiation);
    }

    /**
     * Set the responder URL from the certificate
     * @param cert the certificate
     * @param url the url as String
     * @throws X509ExtensionInitException error case
     * @throws MalformedURLException error case
     */
    public static void setOCSPUrl(X509Certificate cert, String url) throws X509ExtensionException, MalformedURLException {
        AccessDescription description = new AccessDescription(ObjectID.ocsp, url);
        AuthorityInfoAccess access = new AuthorityInfoAccess(description);
        access.setCritical(false);
        cert.addExtension(access);
    }

    public static boolean isCertificateSelfSigned(X509Certificate certificate) {
        try {
            AuthorityKeyIdentifier authKeyID = (AuthorityKeyIdentifier)
                    certificate.getExtension(AuthorityKeyIdentifier.oid);
            SubjectKeyIdentifier subjKeyID = (SubjectKeyIdentifier)
                    certificate.getExtension(SubjectKeyIdentifier.oid);

            if (authKeyID == null) {
                return true;
            } else if (subjKeyID != null && authKeyID != null) {
                return Arrays.equals(authKeyID.getKeyIdentifier(), subjKeyID.get());
            } else {
                return false;
            }
        } catch (Exception ex) {
            throw new IllegalStateException("cannot detect self signed ??!!", ex);
        }

    }
}
