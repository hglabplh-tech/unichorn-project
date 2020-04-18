package org.harry.security.util;

import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.*;
import iaik.x509.SimpleChainVerifier;
import iaik.x509.X509Certificate;
import iaik.x509.X509ExtensionException;
import iaik.x509.extensions.*;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.trustlist.TrustListLoader;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Random;

/**
 * This is a class for generating valid certificate chains and add the
 * CA and issuer to the p12 store and to the trust-list
 * @author Harald Glab-Plhak
 *
 */
public class CertificateWizzard {
    private TrustListLoader loader = new TrustListLoader();
    private KeyPair ca_rsa;
    private KeyPair inter_rsa;
    private X509Certificate caRSA;
    private X509Certificate intermediateRSA;

    private final SimpleChainVerifier verifier = new SimpleChainVerifier();
    private final ConfigReader.MainProperties properties;
    private KeyStore store = null;

    public static String APP_DIR;

    public static String APP_DIR_TRUST;

    public static final String PROP_STORE_NAME = "application.jks";
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
        loader.makeRoot();
        this.properties = properties;
        store = KeyStoreTool.initStore("JKS");
        // for verifying the created certificates

    }

    public KeyStore getStore() {
        return store;
    }

    public TrustListLoader getLoader() {
        return loader;
    }

    public void generateCA() {
        try {
            X509Certificate [] certChain = new X509Certificate[1];
        Name issuer = new Name();
        issuer.addRDN(ObjectID.country,
                properties.getCountry());
        issuer.addRDN(ObjectID.organization ,properties.getOrganization());
        issuer.addRDN(ObjectID.organizationalUnit ,properties.getUnit());

        Name subject = new Name();
        subject.addRDN(ObjectID.country, properties.getCountry());
        subject.addRDN(ObjectID.organization , properties.getOrganization());
        subject.addRDN(ObjectID.organizationalUnit ,properties.getUnit());
        issuer.addRDN(ObjectID.commonName ,properties.getCommonName());
        ca_rsa = generateKeyPair("RSA", 4096);
        caRSA = createCertificate(issuer,
                ca_rsa.getPublic(),
                issuer,
                ca_rsa.getPrivate(),
                (AlgorithmID)AlgorithmID.sha256WithRSAEncryption.clone(),
                null,
                true,
                false);
            caRSA.verify();
            // set the CA cert as trusted root
            verifier.addTrustedCertificate(caRSA);
            certChain[0] = caRSA;
            KeyStoreTool.addKey(store, ca_rsa.getPrivate(),
                    properties.getKeystorePass().toCharArray(),
                    certChain, properties.getCommonName());
        loader.addX509Cert(caRSA);
        } catch (Exception ex) {
            throw new IllegalStateException("certificate generation failed", ex);
        }
    }

    public void generateIntermediate() {
        try {
            X509Certificate [] certChain = new X509Certificate[2];
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
            issuer.addRDN(ObjectID.commonName, properties.getCommonName());
            subject.addRDN(ObjectID.commonName ,properties.getCommonName() + "Inter");
            inter_rsa = generateKeyPair("RSA", 4096);
            intermediateRSA = createCertificate(subject,
                    inter_rsa.getPublic(),
                    issuer,
                    ca_rsa.getPrivate(),
                    (AlgorithmID) AlgorithmID.sha256WithRSAEncryption.clone(),
                    subjectKeyID.get(),
                    true,
                    true);
            certChain[0] = intermediateRSA;
            certChain[1] = caRSA;
            // and verify the chain
            verifier.verifyChain(certChain);
            KeyStoreTool.addKey(store, inter_rsa.getPrivate(),
                    properties.getKeystorePass().toCharArray(),
                    certChain, properties.getCommonName() + "Intermediate");
            loader.addX509Cert(intermediateRSA);
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
            issuer.addRDN(ObjectID.commonName, properties.getCommonName() + "Inter");
            subject.addRDN(ObjectID.commonName ,properties.getCommonName() + "User");
            KeyPair userKeys = generateKeyPair("RSA", 4096);
             X509Certificate userCert = createCertificate(subject,
                    userKeys.getPublic(),
                    issuer,
                    inter_rsa.getPrivate(),
                    (AlgorithmID) AlgorithmID.sha256WithRSAEncryption.clone(),
                    subjectKeyID.get(),
                    true,
                    true);
            certChain[0] = userCert;
            certChain[1] = intermediateRSA;
            certChain[2] = caRSA;
            // and verify the chain
            verifier.verifyChain(certChain);
            KeyStoreTool.addKey(store, userKeys.getPrivate(),
                    properties.getKeystorePass().toCharArray(),
                    certChain, properties.getCommonName() + "User");
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
     * @param signing
     * @param forSigning if the certificate to be created shall be used for signing or encryption
     * @return the certificate just created
     */
    public static X509Certificate createCertificate(Name subject, PublicKey publicKey,
                                                    Name issuer, PrivateKey privateKey, AlgorithmID algorithm, byte[] keyID,
                                                    boolean signing, boolean forSigning) {

        // create a new certificate
        X509Certificate cert = new X509Certificate();

        try {
            // set the values
            cert.setSerialNumber(new BigInteger(20, new Random()));
            cert.setSubjectDN(subject);
            cert.setPublicKey(publicKey);
            cert.setIssuerDN(issuer);

            GregorianCalendar date = new GregorianCalendar();
            // not before now
            cert.setValidNotBefore(date.getTime());

            if (issuer.equals(subject)) {
                // CA certificate
                date.add(Calendar.YEAR, 6);
                BasicConstraints basicConstraints = new BasicConstraints(true);
                cert.addExtension(basicConstraints);
                KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
                cert.addExtension(keyUsage);
            } else {
                date.add(Calendar.YEAR, 5);
                KeyUsage keyUsage = null;
                if (forSigning) {
                    keyUsage = new KeyUsage(KeyUsage.digitalSignature |
                            KeyUsage.nonRepudiation | KeyUsage.keyCertSign | KeyUsage.cRLSign);
                } else {
                    if (publicKey.getAlgorithm().equalsIgnoreCase("ESDH")) {
                        keyUsage = new KeyUsage(KeyUsage.keyAgreement) ;
                    } else {
                        keyUsage = new KeyUsage(KeyUsage.keyEncipherment);
                    }
                }
                cert.addExtension(keyUsage);
                AuthorityKeyIdentifier authID = new AuthorityKeyIdentifier();
                authID.setKeyIdentifier(keyID);
                cert.addExtension(authID);
                GeneralNames generalNames = new GeneralNames();
                generalNames.addName(new GeneralName(GeneralName.rfc822Name, "smimetest@harryglab.com"));
                SubjectAltName subjectAltName = new SubjectAltName(generalNames);
                cert.addExtension(subjectAltName);
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
        } catch (CodingException ex) {
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
                wizzard.getLoader().storeTrust(new FileOutputStream(trustFile));
            } catch(Exception ex) {
                throw new IllegalStateException("could not initialize", ex);
            }
        }
    }

}
