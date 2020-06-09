package org.harry.security.util;

import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.*;
import iaik.pkcs.pkcs1.MGF1ParameterSpec;
import iaik.pkcs.pkcs1.MaskGenerationAlgorithm;
import iaik.pkcs.pkcs1.RSAPssParameterSpec;
import iaik.security.ec.common.ECStandardizedParameterFactory;
import iaik.security.ec.provider.ECCelerate;
import iaik.security.provider.IAIK;
import iaik.security.rsa.RSAPssKeyPairGenerator;
import iaik.security.rsa.RSAPssPrivateKey;
import iaik.security.rsa.RSAPssPublicKey;
import iaik.utils.Util;
import iaik.x509.*;
import iaik.x509.attr.*;
import iaik.x509.attr.attributes.*;
import iaik.x509.attr.extensions.AuditIdentity;
import iaik.x509.attr.extensions.NoRevAvail;
import iaik.x509.attr.extensions.ProxyInfo;
import iaik.x509.attr.extensions.TargetInformation;
import iaik.x509.extensions.*;
import iaik.x509.extensions.qualified.QCStatements;
import iaik.x509.extensions.qualified.structures.QCStatement;
import iaik.x509.extensions.qualified.structures.QCSyntaxV2;
import iaik.x509.extensions.qualified.structures.etsi.*;
import iaik.x509.qualified.QualifiedCertificate;
import org.harry.security.util.bean.AttrCertBean;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.trustlist.TrustListLoader;
import org.harry.security.util.trustlist.TrustListManager;


import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;

import static org.harry.security.CommonConst.*;

/**
 * This is a class for generating valid certificate chains and add the
 * CA and issuer to the p12 store and to the trust-list
 * @author Harald Glab-Plhak
 *
 */
public class CertificateWizzard {
    private TrustListLoader loader = new TrustListLoader(false);
    private TrustListManager manager = null;
    private KeyPair ca_rsa;
    private KeyPair inter_rsa;
    private KeyPair ca_ec;
    private KeyPair inter_ec;
    private X509Certificate caRSA;
    private X509Certificate caEC;
    private X509Certificate intermediateRSA;
    private X509Certificate intermediateEC;
    private final OutputStream attrCertOut;

    private final SimpleChainVerifier verifier = new SimpleChainVerifier();
    private final ConfigReader.MainProperties properties;
    private KeyStore store = null;


    public static final String PROP_STORE_NAME = "application.p12";
    public static final String PROP_TRUST_NAME = "privateTrust.xml";


    /**
     * The CTOr for the wizzard
     * @param properties the MainProperties object
     * @param attrCertOut the output stream defining the target file for the generated AttributeCertificate
     * @param storeType
     */
    public CertificateWizzard(ConfigReader.MainProperties properties, OutputStream attrCertOut, String storeType) {
        try {
            manager = loader.getManager(null);
        } catch (Exception e) {

        }
        this.attrCertOut = attrCertOut;
        this.properties = properties;
        store = KeyStoreTool.initStore(storeType, "geheim");

        // for verifying the created certificates

    }

    /**
     * get the keystore object
     * @return the keystore
     */
    public KeyStore getStore() {
        return store;
    }


    /**
     * get the instance of the used trust-list-loader
     * @return the loader
     */
    public TrustListLoader getLoader() {
        return loader;
    }

    /**
     * Create the Certificates Authority Certificate (self-signed)
     * @param commonName the common name of the certificate
     * @param rsaPSS if true a PSS 2.1 algorithm is used for keypair generation
     * @return the resulting keypair
     */
    public KeyPair generateCA(String commonName, boolean rsaPSS) {
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
        issuer.addRDN(ObjectID.commonName ,commonName +"RSA" );
            String addONString = "";
            if (rsaPSS) {
                ca_rsa = generateKeyPairRSAPSS("RSASSA-PSS", 4096);
                addONString = " RSA-PSS";
            } else {
                ca_rsa = generateKeyPair("RSA", 4096);
            }
        caRSA = newBuilder().setIssuer(issuer)
                .setPublicKey(ca_rsa.getPublic())
                .setSubject(issuer)
                .setPrivateKey(ca_rsa.getPrivate())
                .setAlgorithm((AlgorithmID)AlgorithmID.sha256WithRSAEncryption.clone())
                .setKeyID(null)
                .setKeyUsage(usage).build();
            caRSA.verify();
            // set the CA cert as trusted root
            verifier.addTrustedCertificate(caRSA);
            certChain[0] = caRSA;
            KeyStoreTool.addKey(store, ca_rsa.getPrivate(),
                    properties.getKeystorePass().toCharArray(),
                    certChain, UUID.randomUUID().toString() + "" +
                            "RSA" + addONString);
            issuer.removeRDN(ObjectID.commonName);
            issuer.addRDN(ObjectID.commonName ,properties.getCommonName() +"_EC" );
            ca_ec = generateKeyPairECC(571);
            caEC = newBuilder().setIssuer(issuer)
                    .setPublicKey(ca_ec.getPublic())
                    .setSubject(issuer)
                    .setPrivateKey(ca_ec.getPrivate())
                    .setAlgorithm((AlgorithmID)AlgorithmID.ecdsa.clone())
                    .setKeyID(null)
                    .setKeyUsage(usage).build();

            caEC.verify();
            // set the CA cert as trusted root
            verifier.addTrustedCertificate(caEC);
            certChain[0] = caEC;
            KeyStoreTool.addKey(store, ca_ec.getPrivate(),
                    properties.getKeystorePass().toCharArray(),
                    certChain, UUID.randomUUID().toString() + "_EC");

            List<Vector<String>> paths = manager.collectPaths();
            manager.addX509Cert(paths.get(0), caRSA);
            manager.addX509Cert(paths.get(0),caEC);
        } catch (Exception ex) {
            throw new IllegalStateException("certificate generation failed", ex);
        }
        return ca_rsa;
    }

    /**
     * Create a intermediate certificate used for signing user certificates as well as for
     * the ca there is a RSA and a EC version
     * @param parentKeys the keypair of the ca-certificate
     * @param commonName the common name for the generated certificate
     * @param rsaPSS if true a PSS 2.1 algorithm is used for keypair generation
     * @return the keypair generated by this method
     */
    public KeyPair generateIntermediate(KeyPair parentKeys, String commonName, boolean rsaPSS) {
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
            issuer.addRDN(ObjectID.commonName, commonName + "RSA");
            subject.addRDN(ObjectID.commonName ,commonName + "RSA_Inter");
            String addONString = "";
            if (rsaPSS) {
                inter_rsa = generateKeyPairRSAPSS("RSASSA-PSS", 4096);
                addONString = " RSA-PSS";
            } else {
                inter_rsa = generateKeyPair("RSA", 4096);
            }
            intermediateRSA = createCertificate(subject,
                    inter_rsa.getPublic(),
                    issuer,
                    parentKeys.getPrivate(),
                    (AlgorithmID) AlgorithmID.sha256WithRSAEncryption.clone(),
                    subjectKeyID.get(),
                    usage);
            certChain[0] = intermediateRSA;
            certChain[1] = caRSA;
            // and verify the chain
            verifier.verifyChain(certChain);
            KeyStoreTool.addKey(store, inter_rsa.getPrivate(),
                    properties.getKeystorePass().toCharArray(),
                    certChain, UUID.randomUUID().toString() + "IntermediateRSA" + addONString);
            issuer.removeRDN(ObjectID.commonName);
            issuer.addRDN(ObjectID.commonName ,properties.getCommonName() + "_EC");
            subject.removeRDN(ObjectID.commonName);
            subject.addRDN(ObjectID.commonName ,properties.getCommonName() + "_EC_Inter");
            SubjectKeyIdentifier subjectKeyIDEC = (SubjectKeyIdentifier) caEC.getExtension(SubjectKeyIdentifier.oid);
            inter_ec = generateKeyPairECC( 571);
            intermediateEC = createCertificate(subject,
                    inter_ec.getPublic(),
                    issuer,
                    ca_ec.getPrivate(),
                    (AlgorithmID) AlgorithmID.ecdsa.clone(),
                    subjectKeyIDEC.get(),
                    usage);
            certChain[0] = intermediateEC;
            certChain[1] = caEC;
            // and verify the chain
            verifier.verifyChain(certChain);
            KeyStoreTool.addKey(store, inter_ec.getPrivate(),
                    properties.getKeystorePass().toCharArray(),
                    certChain, UUID.randomUUID().toString() + "IntermediateEC");

            List<Vector<String>> paths = manager.collectPaths();
            manager.addX509Cert(paths.get(0), intermediateRSA);
            manager.addX509Cert(paths.get(0),intermediateEC);
            return inter_rsa;
        } catch (Exception ex) {
            throw new IllegalStateException("certificate generation failed", ex);
        }
    }

    /**
     * Create a user certificate used for signing data as well as for
     * the ca there is a RSA and a EC version
     * @param parentKeys the keypair of the intermediate-certificate
     * @param commonName the common name for the generated certificate
     * @param rsaPSS if true a PSS 2.1 algorithm is used for keypair generation
     */
    public void generateUser(KeyPair parentKeys, String commonName, boolean rsaPSS) {
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
            issuer.addRDN(ObjectID.commonName, commonName + "" +
                    "RSA_Inter");
            subject.addRDN(ObjectID.commonName ,properties.getCommonName() + "_RSA_User");
            KeyPair userKeys = null;
            String addONString = "";
            if (rsaPSS) {
                userKeys = generateKeyPairRSAPSS("RSASSA-PSS", 4096);
                addONString = " RSA-PSS";
            } else {
                userKeys = generateKeyPair("RSA", 4096);
            }
            KeyUsage usage = signUsage();
             X509Certificate userCert = createCertificate(subject,
                    userKeys.getPublic(),
                    issuer,
                    parentKeys.getPrivate(),
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
                    certChain, UUID.randomUUID().toString() + "UserRSA" + addONString);
            issuer.removeRDN(ObjectID.commonName);
            issuer.addRDN(ObjectID.commonName ,properties.getCommonName() + "_EC_Inter");
            subject.removeRDN(ObjectID.commonName);
            subject.addRDN(ObjectID.commonName ,properties.getCommonName() + "_EC_User");
            SubjectKeyIdentifier subjectKeyIDEC = (SubjectKeyIdentifier) intermediateEC.getExtension(SubjectKeyIdentifier.oid);
            KeyPair userKeysEC = generateKeyPairECC(571);
            X509Certificate userCertEC = createCertificate(subject,
                    userKeysEC.getPublic(),
                    issuer,
                    inter_ec.getPrivate(),
                    (AlgorithmID) AlgorithmID.ecdsa.clone(),
                    subjectKeyIDEC.get(), usage);
            certChain[0] = userCertEC;
            certChain[1] = intermediateEC;
            certChain[2] = caEC;
            String[] targetnames = new String[]{"Unichorn Team 1", "Unichorn Team 2", "Unichorn Team 3", "Unichorn Team 4"};
            AttrCertBean attrBean = new AttrCertBean()
                    .setRoleName("urn:signer")
                    .setCommonName("Common Signer Author")
                    .setTargetName("Unichorn Signer")
                    .setTargetNames(targetnames)
                    .setTargetGroup("Unichorn Signing Group")
                    .setAuthCountry("DE")
                    .setAuthOrganization("Unichorn Signing GmbH")
                    .setAuthOrganizationalUnit("Unichorn Signing Development Team")
                    .setAuthCommonName("Unichorn Signers Group")
                    .setCategory("signing")
                    .setAccessIdentityService("www.unichorn-signing.de")
                    .setAccessIdentityIdent("signingId")
                    .setGroupValue1("Developers Certificates 1")
                    .setGroupValue2("Developers Certificates 2");
            AttributeCertificate attrCert = createAttributeCertificate(userCert, intermediateRSA,
                    inter_rsa.getPrivate(), attrBean);
            // and verify the chain
            verifier.verifyChain(certChain);
            attrCert.writeTo(this.attrCertOut);
            KeyStoreTool.addKey(store, userKeysEC.getPrivate(),
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
        KeyUsage usage = new KeyUsage();

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
                setOCSPUrl(cert, OCSP_URL);

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
            cert.addExtension(addQualifiedExtension());
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


    /**
     * Generate a RSA_PSS keypair
      * @param algorithm the algorithm
     *  @param bits the bit-length
     *  @return the key-pair
     */
    public static KeyPair generateKeyPairRSAPSS(String algorithm, int bits) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, "IAIK");
            RSAPssKeyPairGenerator rsaPsskeyGen = (RSAPssKeyPairGenerator) generator;
            // create PSS parameters for specifying hash, mgf algorithms and salt length:
            // hash and mgf algorithm ids
            AlgorithmID hashID = (AlgorithmID) AlgorithmID.sha256.clone(); // ???
            AlgorithmID mgfID = (AlgorithmID) AlgorithmID.mgf1.clone();
            mgfID.setParameter(hashID.toASN1Object());
            int saltLength = 64;
            // hash and mgf engines
            MessageDigest hashEngine = hashID.getMessageDigestInstance();

            MaskGenerationAlgorithm mgfEngine = mgfID.getMaskGenerationAlgorithmInstance();
            iaik.pkcs.pkcs1.MGF1ParameterSpec mgf1ParamSpec = new MGF1ParameterSpec(hashID);
            mgf1ParamSpec.setHashEngine(hashEngine);
            mgfEngine.setParameters(mgf1ParamSpec);
            // create the RSAPssParameterSpec
            RSAPssParameterSpec pssParamSpec = new RSAPssParameterSpec(hashID, mgfID, saltLength);
            // set engines
            pssParamSpec.setHashEngine(hashEngine);
            pssParamSpec.setMGFEngine(mgfEngine);
            // initialize key pair generator
            rsaPsskeyGen.initialize(bits, pssParamSpec);
            KeyPair keyPair = rsaPsskeyGen.generateKeyPair();
            RSAPssPublicKey publicKey = (RSAPssPublicKey) keyPair.getPublic();
            RSAPssPrivateKey privateKey = (RSAPssPrivateKey) keyPair.getPrivate();
            return keyPair;
        } catch (Exception ex) {
            throw new IllegalStateException("RSA_PSS generation failed", ex);
        }

    }

    /**
     * Create a attribute certificate
     * @param issuer the issuer certificate
     * @param user the user certificate
     * @param issuerPK the user private key
     * @param attrBean the bean holding the values for generation
     * @return
     */
    public static AttributeCertificate createAttributeCertificate(X509Certificate issuer,
                                                                  X509Certificate user,
                                                                  PrivateKey issuerPK,
                                                                  AttrCertBean attrBean) {
        try {

            // only for this sample we create a rudimentary role specification
            // certificate where nothing else is set as holder and issuer fiels
            AttributeCertificate roleSpecificationCert = new AttributeCertificate();
            Name roleIssuer = new Name();
            roleIssuer.addRDN(ObjectID.commonName, attrBean.getCommonName());
            roleSpecificationCert.setIssuer(new V2Form(roleIssuer));
            Holder roleHolder = new Holder();
            GeneralName roleName = new GeneralName(GeneralName.uniformResourceIdentifier,attrBean.getRoleName());
            roleHolder.setEntityName(new GeneralNames(roleName));
            roleSpecificationCert.setHolder(roleHolder);
            // in practice we now would add validity, extensions,... and sign the
            // cert...

            // create Attribute Certificate
            AttributeCertificate attributeCertificate = new AttributeCertificate();
            // issuer
            Name issuerName = (Name) issuer.getSubjectDN();
            V2Form v2Form = new V2Form(issuerName);
            attributeCertificate.setIssuer(v2Form);
            // holder (from base certificate)
            X509Certificate baseCert = user;
            Holder holder = new Holder();
            holder.setBaseCertificateID(baseCert);
            attributeCertificate.setHolder(holder);
            // for this demo we use a ramdomly generated serial number
            Random random = new Random();
            BigInteger serial= BigInteger.valueOf(random.nextLong());
            attributeCertificate.setSerialNumber(serial);
            // validity
            GregorianCalendar c = new GregorianCalendar();
            Date notBeforeTime = c.getTime();
            c.add(Calendar.MONTH, 1);
            Date notAfterTime = c.getTime();
            attributeCertificate.setNotBeforeTime(notBeforeTime);
            attributeCertificate.setNotAfterTime(notAfterTime);
            // add attributes
            addAttributes(attributeCertificate, roleSpecificationCert, attrBean);
            // add extensions
            addExtensions(attributeCertificate, attrBean);
            // sign certificate
            attributeCertificate.sign(AlgorithmID.sha1WithRSAEncryption, issuerPK);

            byte[] test = attributeCertificate.getEncoded();            // send certificate to ...


            // receive certificate
            attributeCertificate = new AttributeCertificate(test);
            System.out.println("Attribute Certificate: ");
            System.out.println(attributeCertificate.toString(true));
            // verify signature

            return attributeCertificate;


        } catch (Exception ex) {
            ex.printStackTrace();
            throw new RuntimeException();
        }


    }



    /**
     * Creates and adds some attribute certificate extensions. The following
     * extensions are added:
     * <ul>
     * <li>iaik.x509.attr.extensions.AuditIdentity
     * <li>iaik.x509.attr.extensions.NoRevAvail
     * <li>iaik.x509.attr.extensions.TargetInformation
     * <li>iaik.x509.attr.extensions.ProxyInfo
     * </ul>
     *
     * @param attributeCertificate
     *          the attribute certificate to which the extensions shall be added
     *
     * @throws Exception
     *           if an error occurs while creating/adding the extensions
     */
    private static void addExtensions(AttributeCertificate attributeCertificate, AttrCertBean attrBean)
            throws Exception
    {

        // AuditIdentity extension
        byte[] auditValue = { 1, 1, 1, 1, 1, 1, 1, 1 };
        AuditIdentity auditIdentity = new AuditIdentity(auditValue);
        attributeCertificate.addExtension(auditIdentity);

        // NoRevAvail extension
        NoRevAvail noRevAvail = new NoRevAvail();
        attributeCertificate.addExtension(noRevAvail);

        // TargetInformation extension
        TargetInformation targetInformation = new TargetInformation();
        // create and add a TargetName
        GeneralName name = new GeneralName(GeneralName.uniformResourceIdentifier,
                attrBean.getTargetName());
        TargetName targetName = new TargetName(name);
        targetInformation.addTargetElement(targetName);
        // create and add a TargetGroup
        GeneralName groupName = new GeneralName(GeneralName.dNSName, attrBean.getTargetGroup());
        TargetGroup targetGroup = new TargetGroup(groupName);
        targetInformation.addTargetElement(targetGroup);
        // add extension
        attributeCertificate.addExtension(targetInformation);

        // ProxyInfo extension
        ProxyInfo proxyInfo = new ProxyInfo();
        // add two Targets
        TargetName targetName1 = new TargetName(new GeneralName(
                GeneralName.uniformResourceIdentifier, attrBean.getTargetNames()[0]));
        TargetName targetName2 = new TargetName(new GeneralName(
                GeneralName.uniformResourceIdentifier, attrBean.getTargetNames()[1]));
        // first Targets (ProxySet)
        Targets targets1 = new Targets();
        targets1.setTargets(new Target[] { targetName1, targetName2 });
        proxyInfo.addTargets(targets1);
        TargetName targetName3 = new TargetName(new GeneralName(
                GeneralName.uniformResourceIdentifier, attrBean.getTargetNames()[2]));
        TargetName targetName4 = new TargetName(new GeneralName(
                GeneralName.uniformResourceIdentifier, attrBean.getTargetNames()[3]));
        // second Targets (ProxySet)
        Targets targets2 = new Targets();
        targets2.addTarget(targetName3);
        targets2.addTarget(targetName4);
        proxyInfo.addTargets(targets2);
        // add extension
        attributeCertificate.addExtension(proxyInfo);

    }

    /**
     * Creates and adds some attributes. The following attributes are added:
     * <ul>
     * <li>{@link iaik.x509.attr.attributes.AccessIdentity AccessIdentity}
     * <li>{@link iaik.x509.attr.attributes.ChargingIdentity ChargingIdentity}
     * <li>{@link iaik.x509.attr.attributes.Clearance Clearance}
     * <li>{@link iaik.x509.attr.attributes.Group Group}
     * <li>{@link iaik.x509.attr.attributes.Role Role}
     * <li>{@link iaik.x509.attr.attributes.ServiceAuthenticationInfo
     * ServiceAuthenticationInfo}
     * </ul>
     *
     * @param attributeCertificate
     *          the attribute certificate to which the attributes shall be added
     *
     * @throws Exception
     *           if an error occurs while creating/adding the extensions
     */
    private static void addAttributes(AttributeCertificate attributeCertificate,
                                      AttributeCertificate roleSpecificationCert,
                                      AttrCertBean attrBean)
            throws Exception
    {
        try {

            // AccessIdentity
            GeneralName aiService = new GeneralName(GeneralName.uniformResourceIdentifier,
                    attrBean.getAccessIdentityService());
            GeneralName aiIdent = new GeneralName(GeneralName.rfc822Name,
                    attrBean.getAccessIdentityIdent());
            AccessIdentity accessIdentity = new AccessIdentity(aiService, aiIdent);
            // add AccessIdentity attribute
            attributeCertificate.addAttribute(new Attribute(accessIdentity));

            // Charging Identity
            ObjectID[] ciValues = { ObjectID.iaik };
            ChargingIdentity chargingIdentity = new ChargingIdentity(ciValues);
            // set policy authority
            Name name = new Name();
            name.addRDN(ObjectID.country, attrBean.getAuthCountry());
            name.addRDN(ObjectID.organization, attrBean.getAuthOrganization());
            name.addRDN(ObjectID.organizationalUnit, attrBean.getAuthOrganizationalUnit());
            name.addRDN(ObjectID.commonName, attrBean.getAuthCommonName());
            GeneralName policyName = new GeneralName(GeneralName.directoryName, name);
            GeneralNames policyAuthority = new GeneralNames(policyName);
            chargingIdentity.setPolicyAuthority(policyAuthority);
            // add ChargingIdentity attribute
            attributeCertificate.addAttribute(new Attribute(chargingIdentity));

            // Clearance
            ObjectID policyId = new ObjectID("1.3.6.1.4.1.2706.2.2.1.6.1.2");
            Clearance clearance = new Clearance(policyId);
            // class list
            int classList = Clearance.TOP_SECRET;
            clearance.setClassList(classList);
            // register SecurityCategory
            SecurityCategory.register(MySecurityCategory.type, MySecurityCategory.class);
            SecurityCategory[] categories = { new MySecurityCategory(attrBean.getCategory()) };
            clearance.setSecurityCategories(categories);
            // add Clearance attribute
            attributeCertificate.addAttribute(new Attribute(clearance));

            // Group
            String gValue1 = attrBean.getGroupValue1();
            String gValue2 = attrBean.getGroupValue2();
            String[] gValues = { gValue1, gValue2 };
            Group group = new Group(gValues);
            // add Group attribute
            attributeCertificate.addAttribute(new Attribute(group));

            // Role
            GeneralName roleName = new GeneralName(GeneralName.uniformResourceIdentifier,attrBean.getRoleName());
            Role role = new Role(roleName);
            // set role authority to the issuer of the corresponding role
            // specification cert
            role.setRoleAuthority(roleSpecificationCert);
            // add Role attribute
            attributeCertificate.addAttribute(new Attribute(role));

            // ServiceAuthenticationInfo
            GeneralName service = new GeneralName(GeneralName.uniformResourceIdentifier,
                    attrBean.getAccessIdentityService());
            GeneralName ident = new GeneralName(GeneralName.rfc822Name,
                    attrBean.getAccessIdentityIdent());
            ServiceAuthenticationInfo serviceAuthInf = new ServiceAuthenticationInfo(service,
                    ident);
            byte[] authInfo = Util.toASCIIBytes("topSecret");
            serviceAuthInf.setAuthInfo(authInfo);
            // add ServiceAuthenticationInformation attribute
            attributeCertificate.addAttribute(new Attribute(serviceAuthInf));

        } catch (Exception ex) {
            System.err.println("Error adding attribute: " + ex.toString());
            throw ex;
        }
    }


    /**
     * Initialize the application key-store and trust list to work with the responder
     */
    public static void initThis() {
        File keystore = new File(APP_DIR, PROP_STORE_NAME);
        File trustFile = new File(APP_DIR_TRUST, PROP_TRUST_NAME);
        if (!keystore.exists() && !trustFile.exists()) {
            ConfigReader.MainProperties properties = ConfigReader.loadStore();
            properties.setKeystorePass("geheim");
            try {
                FileOutputStream stream = new FileOutputStream(properties.getAttrCertPath());
                CertificateWizzard wizzard = new CertificateWizzard(properties, stream, "PKCS12");
                KeyPair caKeys = wizzard.generateCA(properties.getCommonName(), false);
                KeyPair interKeys = wizzard.generateIntermediate(caKeys, properties.getCommonName(), false);
                wizzard.generateUser(interKeys, properties.getCommonName(), false);
                KeyStoreTool.storeKeyStore(wizzard.getStore(),
                        new FileOutputStream(keystore),
                        properties.getKeystorePass().toCharArray());
                wizzard.getLoader().storeTrust(new FileOutputStream(trustFile));
            } catch(Exception ex) {
                throw new IllegalStateException("could not initialize", ex);
            }
        }
    }

    public static void generateThis() {

        ConfigReader.MainProperties properties = ConfigReader.loadStore();
        generateThis(properties);
    }

    /**
     * Initialize a keystore used for signing e.g.
     * @param properties the application properties
     */
    public static void generateThis(ConfigReader.MainProperties properties) {

        if (properties == null) {
            properties = ConfigReader.loadStore();
        }
        File keystore = new File(properties.getKeystorePath());
        File keystoreEC = new File(properties.getKeystorePath() + "_EC");
        properties.setKeystorePass("geheim");
        try {
            FileOutputStream stream = new FileOutputStream(properties.getAttrCertPath());
            CertificateWizzard wizzard = new CertificateWizzard(properties, stream, "PKCS12");
            KeyPair caKeys = wizzard.generateCA(properties.getCommonName(), false);
            KeyPair interKeys = wizzard.generateIntermediate(caKeys, properties.getCommonName(), false);
            wizzard.generateUser(interKeys, properties.getCommonName(), false);

            KeyStoreTool.storeKeyStore(wizzard.getStore(),
                    new FileOutputStream(keystore),
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
                    .getParametersByName("secp256r1");


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

    public static V3Extension addQualifiedExtension() throws X509ExtensionException {

        Vector extensions = new Vector();
        // register QCEuCompliance as indicating a qualified certificate
        QualifiedCertificate
                .registerQualifiedQCStatementIDs(new ObjectID[] { QcEuCompliance.statementID });


        // QCSyntaxV2
        ObjectID semID = new ObjectID("1.3.6.1.4.1.2706.2.2.1.3");
        GeneralName[] genNames = new GeneralName[1];
        genNames[0] = new GeneralName(GeneralName.uniformResourceIdentifier,
                "http//ca.iaik.at/registrationAuthority");
        QCSyntaxV2 qcSyntaxV2 = new QCSyntaxV2(semID, genNames);

        // QCEuCompliance
        QcEuCompliance qcCompliance = new QcEuCompliance();

        // QcEuRetentionPeriod
        int retentionPeriod = 10;
        QcEuRetentionPeriod qcRetentionPeriod = new QcEuRetentionPeriod(retentionPeriod);

        // QcEuLimitValue
        String currency = "EUR";
        int amount = 1;
        int exponent = 4;
        QcEuLimitValue qcLimitValue = new QcEuLimitValue(currency, amount, exponent);

        // QcEuSSCD
        QcEuSSCD qcSSCD = new QcEuSSCD();

        // QcEuPDS
        QcEuPDS qcEuPDS = new QcEuPDS();
        qcEuPDS.addPdsLocation(new QcEuPDS.PdsLocation("https://localhost", "de"));
        qcEuPDS.addPdsLocation(new QcEuPDS.PdsLocation("https://localhost", "en"));

        // QcType
        ObjectID qcTypeID = QcType.ID_ETSI_QCT_ESIGN;
        QcType qcType = new QcType(qcTypeID);
        qcType.addQcTypeID(QcType.ID_ETSI_QCT_ESEAL);

        QCStatement[] qcStatements = new QCStatement[8];
        qcStatements[0] = new QCStatement(qcSyntaxV2);
        // we add a QCStatement consisting only of a statementId and no
        // statementInfo
        ObjectID newStatementID = new ObjectID("1.3.6.1.4.1.2706.2.2.1.5", "NewQCStatement");
        qcStatements[1] = new QCStatement(newStatementID);
        qcStatements[2] = new QCStatement(qcCompliance);
        qcStatements[3] = new QCStatement(qcRetentionPeriod);
        qcStatements[4] = new QCStatement(qcLimitValue);
        qcStatements[5] = new QCStatement(qcSSCD);
        qcStatements[6] = new QCStatement(qcEuPDS);
        qcStatements[7] = new QCStatement(qcType);

        QCStatements qcStatementsExt = new QCStatements(qcStatements);
        return qcStatementsExt;


    }

    public static  CertificateBuilder newBuilder() {
        return new CertificateBuilder();
    }

    public static class CertificateBuilder {
        Name subject;
        PublicKey publicKey;
        Name issuer;
        PrivateKey privateKey;
        AlgorithmID algorithm;
        byte[] keyID;
        KeyUsage keyUsage;

        public CertificateBuilder() {

        }

        public CertificateBuilder setSubject(Name subject) {
            this.subject = subject;
            return this;
        }

        public CertificateBuilder setPublicKey(PublicKey publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        public CertificateBuilder setIssuer(Name issuer) {
            this.issuer = issuer;
            return this;
        }

        public CertificateBuilder setPrivateKey(PrivateKey privateKey) {
            this.privateKey = privateKey;
            return this;
        }

        public CertificateBuilder setAlgorithm(AlgorithmID algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public CertificateBuilder setKeyID(byte[] keyID) {
            this.keyID = keyID;
            return this;
        }

        public CertificateBuilder setKeyUsage(KeyUsage keyUsage) {
            this.keyUsage = keyUsage;
            return this;
        }

        public X509Certificate build () {
            return createCertificate(this.subject,
                    this.publicKey,
                    this.issuer,
                    this.privateKey,
                    this.algorithm,
                    this.keyID,
                    this.keyUsage);
        }
    }
}
