package org.harry.security.pkcs11;

import iaik.asn1.ObjectID;
import iaik.cms.*;
import iaik.cms.pkcs11.IaikPkcs11SecurityProvider;
import iaik.pdf.parameters.PadesBESParameters;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.SessionInfo;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.objects.WTLSCertificate;
import iaik.pkcs.pkcs11.objects.X509AttributeCertificate;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.TokenKeyStore;
import iaik.pkcs.pkcs11.provider.TokenManager;
import iaik.security.provider.IAIK;
import iaik.x509.X509Certificate;
import iaik.x509.attr.AttributeCertificate;
import iaik.x509.extensions.ExtendedKeyUsage;
import org.harry.security.util.*;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.trustlist.TrustListManager;

import javax.activation.DataSource;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.*;

import static org.harry.security.CommonConst.APP_DIR_DLL;

public class CardManager {
    /**
     * The PKCS#11 JCE provider.
     */
    protected static IAIKPkcs11 pkcs11Provider_;

    /**
     * The PKCS#11 JCE provider.
     */
    protected static boolean initialized = false;

    /**
     * The IAIK JCE software provider.
     */
    protected IAIK iaikSoftwareProvider_;

    /**
     * The name of the file that contains the data to be signed.
     */
    protected String fileToBeSigned_;

    /**
     * The name of the signed file.
     */
    protected String outputFile_;

    /**
     * The key store that represents the token (smart card) contents.
     */
    protected TokenKeyStore tokenKeyStore_;

    /**
     * The signature key. In this case only a proxy object, but the application cannot see this.
     */
    protected PrivateKey signatureKey_ = null;

    /**
     * This is the certificate used for verifying the signature. In contrast to the signature key,
     * this key holds the actual keying material.
     */
    protected X509Certificate signerCertificate_ = null;

    protected List<X509Certificate> certificates = new ArrayList<X509Certificate>();

    protected List<AttributeCertificate> attrCertificates = new ArrayList<>();

    protected List<iaik.pkcs.pkcs11.objects.PublicKey> publicKeys = new ArrayList<>();

    protected List<iaik.pkcs.pkcs11.objects.PrivateKey> privateKeys = new ArrayList<>();

    protected Session session = null;



    /**
     * Creates a SignedDataStreamDemo object for the given module name.
     *

     */
    public CardManager() {

        if (!initialized) {
            // special care is required during the registration of the providers
            Properties props = new Properties();
            File wrapperDll = new File(APP_DIR_DLL, "pkcs11wrapper.dll");
            File nativeDll = new File(APP_DIR_DLL, "P11TCOS3NetKey64.dll");
            props.setProperty("PKCS11_NATIVE_MODULE", nativeDll.getAbsolutePath());
            props.setProperty("PKCS11_WRAPPER_PATH", wrapperDll.getAbsolutePath());
            pkcs11Provider_ = new IAIKPkcs11(props);
            initialized = true;
        }
        // IAIKPkcs11.insertProviderAtForJDK14(pkcs11Provider_, 1); // add IAIK PKCS#11 JCE provider as
        // first, use JDK 1.4 bug workaround

        iaikSoftwareProvider_ = new IAIK();
        Security.addProvider(iaikSoftwareProvider_); // add IAIK softweare JCE provider
        Security.addProvider(pkcs11Provider_);

        // set CMS security provider
        IaikPkcs11SecurityProvider pkcs11CmsSecurityProvider = new IaikPkcs11SecurityProvider(
                pkcs11Provider_);
        SecurityProvider.setSecurityProvider(pkcs11CmsSecurityProvider);

    }

    public void setPIN(String cardPINOld, String cardPINNew) throws Exception{
        TokenManager manager = pkcs11Provider_.getTokenManager();
        Session session = manager.getToken().openSession(Token.SessionType.SERIAL_SESSION,
                Token.SessionReadWriteBehavior.RW_SESSION, null, null);
        session.setPIN(cardPINOld.toCharArray(), cardPINNew.toCharArray());
    }

    public void readCardData(String pin) throws Exception {
        TokenManager manager = pkcs11Provider_.getTokenManager();

        if (signatureKey_ == null || signerCertificate_ == null) {
            session = manager.getToken().openSession(Token.SessionType.SERIAL_SESSION,
                    Token.SessionReadWriteBehavior.RO_SESSION, null, null);
            session.login(Session.UserType.USER, pin.toCharArray());
        }
        SessionInfo sessionInfo = session.getSessionInfo();
        System.out.println(" using session:");
        System.out.println(sessionInfo);
        session.findObjectsInit(null);
        Object[] objects = session.findObjects(1);
        while (objects != null && objects.length > 0) {
            for (Object obj : objects) {
                if (obj instanceof X509PublicKeyCertificate) {
                    X509Certificate certificate = getCertificate(obj);
                    System.out.println(certificate.toString(true));
                    certificates.add(certificate);
                    if (checkCertificate(certificate)) {
                        signerCertificate_ = certificate;
                    }
                } else if (obj instanceof X509AttributeCertificate) {
                    AttributeCertificate certificate = getAttrCertificate(obj);
                    System.out.println(certificate.toString(true));

                    attrCertificates.add(certificate);
                } else if (obj instanceof WTLSCertificate) {
                    System.out.println("WTLSCertificate user defined certificate");
                    System.out.println("Object found: " + obj.toString());
                } else if (obj instanceof iaik.pkcs.pkcs11.objects.Certificate) {
                    System.out.println("Individual user defined certificate");
                    System.out.println("Object found: " + obj.toString());
                }else if(obj instanceof iaik.pkcs.pkcs11.objects.PublicKey) {
                    System.out.println("Public key found");
                    publicKeys.add((iaik.pkcs.pkcs11.objects.PublicKey) obj);
                }else if(obj instanceof iaik.pkcs.pkcs11.objects.PrivateKey) {
                    System.out.println("Public key found");
                    privateKeys.add((iaik.pkcs.pkcs11.objects.PrivateKey) obj);
                } else {
                    if(Object.getVendorDefinedObjectBuilder() != null) {
                        Object.VendorDefinedObjectBuilder builder = Object.getVendorDefinedObjectBuilder();
                        java.lang.Object object = builder.build(session, obj.getObjectHandle());
                        System.out.println("Vendor object clazz : " + object.getClass().getCanonicalName());
                    }
                    System.out.println("Object found: " + obj.toString());
                    System.out.println("Object vendor clazz found: " + obj.getClass().getCanonicalName());
                }

            }
            objects = session.findObjects(1);
        }
        session.closeSession();

    }

    /**
     * This method gets the key store of the PKCS#11 provider and stores a reference at
     * <code>pkcs11ClientKeystore_</code>.
     *
     * @exception GeneralSecurityException
     *              If anything with the provider fails.
     * @exception IOException
     *              If loading the key store fails.
     */
    public void getKeyStore(String pin) throws GeneralSecurityException, IOException {
        TokenKeyStore tokenKeyStore = null;
        tokenKeyStore = pkcs11Provider_.getTokenManager().getKeyStore();

        tokenKeyStore_ = tokenKeyStore;
        if (tokenKeyStore == null) {
            System.out
                    .println("Got no key store. Ensure that the provider is properly configured and installed.");
            throw new GeneralSecurityException("Got no key store.");
        }
        tokenKeyStore.load(null, pin.toCharArray()); // this call binds the keystore to the first instance of the
        // IAIKPkcs11 provider

        tokenKeyStore_ = tokenKeyStore;
        Enumeration<String> aliases = tokenKeyStore_.aliases();
        while(aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println(alias);
            Key key = tokenKeyStore_.getKey(alias, pin.toCharArray());
            if (key instanceof RSAPrivateCrtKey) {
                RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey)key;
                if (signerCertificate_.getPublicKey() instanceof java.security.interfaces.RSAPublicKey) {
                    boolean matches = privateMatchesPublic(rsaKey, (java.security.interfaces.RSAPublicKey)signerCertificate_.getPublicKey());
                    if (matches) {
                        signatureKey_ = rsaKey;
                    }

                }

            }
        }
    }

    /**
     * This method gets the key stores of all inserted (compatible) smart cards and simply takes the
     * first key-entry. From this key entry it takes the private key and the certificate to retrieve
     * the public key from. The keys are stored in the member variables <code>signerKey_
     * </code> and <code>signerCertificate_</code>.
     *
     * @exception GeneralSecurityException
     *              If anything with the provider fails.
     * @exception IOException
     *              If loading the key store fails.
     */
    protected void getSignatureKey(String alias) throws GeneralSecurityException,
            IOException {

        if (alias == null) {
            // we simply take the first keystore, if there are serveral
            Enumeration aliases = tokenKeyStore_.aliases();

            // and we take the first signature (private) key for simplicity
            while (aliases.hasMoreElements()) {
                String keyAlias = aliases.nextElement().toString();
                Key key = null;
                try {
                    key = tokenKeyStore_.getKey(keyAlias, null);
                } catch (NoSuchAlgorithmException ex) {
                    throw new GeneralSecurityException(ex.toString());
                }

                if (key instanceof PrivateKey) {
                    Certificate[] certificateChain = tokenKeyStore_.getCertificateChain(keyAlias);
                    if ((certificateChain != null) && (certificateChain.length > 0)) {
                        X509Certificate signerCertificate = (X509Certificate) certificateChain[0];
                        boolean[] keyUsage = signerCertificate.getKeyUsage();
                        if ((keyUsage == null) || keyUsage[0] || keyUsage[1]) { // check for digital signature
                            // or non-repudiation, but also
                            // accept if none set
                            System.out.println("##########");
                            System.out.println("The signer key is: " + key);
                            System.out.println("##########");
                            // get the corresponding certificate for this signer key
                            System.out.println("##########");
                            System.out.println("The signer certificate is:");
                            System.out.println(signerCertificate.toString());
                            System.out.println("##########");
                            signatureKey_ = (PrivateKey) key;
                            signerCertificate_ = signerCertificate;
                            break;
                        }
                    }
                }
            }

        } else {
            System.out.println("using signature key with alias: " + alias);
            signatureKey_ = (PrivateKey) tokenKeyStore_.getKey(alias, null);
            signerCertificate_ = (X509Certificate) tokenKeyStore_.getCertificate(alias);
        }

        if (signatureKey_ == null) {
            System.out
                    .println("Found no signature key. Ensure that a valid card is inserted and contains a key that is suitable for signing.");
            throw new GeneralSecurityException("Found no signature key.");
        } else {
            System.out.println("##########");
            System.out.println("The signature key is: " + signatureKey_);
            System.out.println("##########");
            // get the corresponding certificate for this signature key
            System.out.println("##########");
            System.out.println("The signer certificate is:");
            System.out.println(signerCertificate_.toString());
            System.out.println("##########");
        }
    }


    public DataSource sign(SigningBean signingBean, boolean upgrade, List<TrustListManager> walkers) throws Exception {
        System.out.println("##########");
        System.out.print("Signing data... ");
        iaik.x509.X509Certificate iaikSignerCertificate =  (signerCertificate_ instanceof iaik.x509.X509Certificate) ?
                (iaik.x509.X509Certificate) signerCertificate_
                : new iaik.x509.X509Certificate(signerCertificate_.getEncoded());
        iaik.x509.X509Certificate[] chain;
        AlgorithmPathChecker checker = new AlgorithmPathChecker(walkers, signingBean);
        VerificationResults.SignerInfoCheckResults results = new VerificationResults.SignerInfoCheckResults();
        chain = checker.detectChain(iaikSignerCertificate, null, results);
        CertWriterReader.KeyStoreBean bean = new CertWriterReader.KeyStoreBean(chain, signatureKey_);
        signingBean = signingBean.setKeyStoreBean(bean);

        if (signingBean.getSignatureType().equals(SigningBean.SigningType.CMS)) {
            SigningUtil util = new SigningUtil();
            return util.signCMS(signingBean);
        } else if (signingBean.getSignatureType().equals(SigningBean.SigningType.CAdES)) {
            SigningUtil util = new SigningUtil();
            return util.signCAdES(signingBean, upgrade);
        } else if (signingBean.getSignatureType().equals(SigningBean.SigningType.PAdES)) {
            SignPDFUtil util = new SignPDFUtil(signatureKey_, chain);
            PadesBESParameters params = util.createParameters(signingBean);
            return util.signPDF(signingBean, params, pkcs11Provider_.getName());
        }  else {
            return null;
        }
    }




    public byte[] verify() throws GeneralSecurityException, CMSException, IOException, SignatureException {
        System.out.println("##########");
        System.out.println("Verifying signature");

        InputStream inputStream = new FileInputStream(outputFile_);
        SignedDataStream signedData = new SignedDataStream(inputStream);

        if (signedData.getMode() == SignedDataStream.EXPLICIT) {
            // explicitly set the data received by other means
            signedData.setInputStream(new FileInputStream(fileToBeSigned_));
        }

        // read data
        InputStream signedDataInputStream = signedData.getInputStream();

        ByteArrayOutputStream
                contentOs = new ByteArrayOutputStream();
        byte[] buffer = new byte[2048];
        int bytesRead;
        while ((bytesRead = signedDataInputStream.read(buffer)) >= 0) {
            contentOs.write(buffer, 0, bytesRead);
        }

        // get the signer infos
        SignerInfo[] signerInfos = signedData.getSignerInfos();
        // verify the signatures
        for (int i = 0; i < signerInfos.length; i++) {
            try {
                // verify the signature for SignerInfo at index i
                X509Certificate signerCertificate = signedData.verify(i);
                // if the signature is OK the certificate of the signer is returned
                System.out.println("Signature OK from signer: "
                        + signerCertificate.getSubjectDN());
            } catch (SignatureException ex) {
                // if the signature is not OK a SignatureException is thrown
                throw new SignatureException("Signature ERROR: " + ex.getMessage());
            }
        }
        System.out.println("##########");
        // return the content
        return contentOs.toByteArray();
    }

    private X509Certificate getCertificate(Object object) throws Exception {
        CertificateFactory x509CertificateFactory = null;
        byte[] encodedCertificate = ((X509PublicKeyCertificate) object)
                .getValue().getByteArrayValue();
        if (x509CertificateFactory == null) {
            x509CertificateFactory = CertificateFactory.getInstance("X.509");
        }
        Certificate certificate = x509CertificateFactory
                .generateCertificate(new ByteArrayInputStream(encodedCertificate));
        if (certificate != null) {
            X509Certificate iaik = new X509Certificate(certificate.getEncoded());
            System.out.println("Certificate: " + iaik.toString());
            System.out.println("Issuer : " + iaik.getIssuerDN().getName());
            return iaik;
        }
        return null;
    }

    private AttributeCertificate getAttrCertificate(Object object) throws Exception {
        CertificateFactory x509CertificateFactory = null;
        byte[] encodedCertificate = ((X509PublicKeyCertificate) object)
                .getValue().getByteArrayValue();
        if (encodedCertificate != null) {
            AttributeCertificate attributeCert = new AttributeCertificate(encodedCertificate);
            return attributeCert;
        }
        return null;
    }


    /**
     * This method checks a loaded certificate for being a signing certificate
     * @param cert the certificate
     * @return success if it is a signing certificate
     */
    private static boolean checkCertificate(X509Certificate cert) {
        boolean selected = false;
        try {

            Principal principal = cert.getSubjectDN();
            String name = principal.getName();
            ExtendedKeyUsage extendedKeyUsage = (ExtendedKeyUsage)cert.getExtension(ObjectID.certExt_ExtendedKeyUsage);
            cert.checkValidity();
            int count = 0;
            boolean [] keyUsage = cert.getKeyUsage();
            if (keyUsage != null) {
                if (keyUsage[0]) {
                    count++;
                }
            }




            if (extendedKeyUsage != null) {
                ObjectID[] ids = extendedKeyUsage.getKeyPurposeIDs();
                for (ObjectID id : Arrays.asList(ids)) {
                    if (id.equals(ExtendedKeyUsage.emailProtection)) {
                        count++;
                    }

                }
            }
            selected = (count == 2);
        } catch (Exception e) {
            // do nothing
            selected = false;
        }
        return  selected;
    }

    private boolean privateMatchesPublic(RSAPrivateCrtKey privKey, java.security.interfaces.RSAPublicKey pubKey) {
        if (privKey.getModulus().equals(pubKey.getModulus())) {
            if (privKey.getPublicExponent().equals(pubKey.getPublicExponent())) {
                return true;
            }
        }
        return false;
    }
    /**
     * Print information how to use this demo class.
     */
    public void releaseResource() {
        if (tokenKeyStore_ != null) {
            tokenKeyStore_.logout();
        }
    }

    public static IAIKPkcs11 getPkcs11Provider_() {
        return pkcs11Provider_;
    }

    public static boolean isInitialized() {
        return initialized;
    }

    public IAIK getIaikSoftwareProvider_() {
        return iaikSoftwareProvider_;
    }

    public String getFileToBeSigned_() {
        return fileToBeSigned_;
    }

    public String getOutputFile_() {
        return outputFile_;
    }

    public TokenKeyStore getTokenKeyStore_() {
        return tokenKeyStore_;
    }

    public PrivateKey getSignatureKey_() {
        return signatureKey_;
    }

    public X509Certificate getSignerCertificate_() {
        return signerCertificate_;
    }

    public List<X509Certificate> getCertificates() {
        return certificates;
    }

    public List<AttributeCertificate> getAttrCertificates() {
        return attrCertificates;
    }

    public List<iaik.pkcs.pkcs11.objects.PublicKey> getPublicKeys() {
        return publicKeys;
    }

    public List<iaik.pkcs.pkcs11.objects.PrivateKey> getPrivateKeys() {
        return privateKeys;
    }
}
