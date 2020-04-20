package org.harry.security.util;

import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.*;
import iaik.cms.attributes.CMSContentType;
import iaik.cms.attributes.SigningTime;
import iaik.pdf.cmscades.CadesSignatureStream;
import iaik.pdf.parameters.CadesBESParameters;
import iaik.pdf.parameters.CadesTParameters;
import iaik.smime.ess.SigningCertificate;
import iaik.x509.X509Certificate;
import org.harry.security.util.algoritms.DigestAlg;
import org.harry.security.util.algoritms.SignatureAlg;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.CertWriterReader;

import javax.activation.DataSource;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidParameterSpecException;

public class SigningUtil {

    private CertWriterReader.KeyStoreBean keyStoreBean;
    private int mode = SignedDataStream.EXPLICIT;
    private String signaturePath;
    private ConfigReader.MainProperties properties;

    public static String APP_DIR;

    public static final String KEYSTORE_FNAME = "appKeyStore.jks";

    static {
        String userDir = System.getProperty("user.home");
        userDir = userDir + "\\AppData\\Local\\MySigningApp";
        File dir = new File(userDir);
        if (!dir.exists()){
            dir.mkdirs();
        }
        APP_DIR= userDir;
    }


    public SigningUtil() {

    }

    /**
     * singns CMS
     * @param signingBean the parameters
     * @return the data-source with the signature
     */
    public DataSource signCMS(SigningBean signingBean)  {

        try {


            InputStreamDataSource ds = getInputStreamSigDataSource(signingBean);
            return ds;
        } catch (Exception e) {
            throw new IllegalStateException("error occured", e);
        }


    }

    /**
     * The method signs content with a well defined CAdES signature possibly containing time-stamps
     * @param signingBean the bean containing the parameters
     * @return the data source containing the signature
     */
    public DataSource signCAdES(SigningBean signingBean)  {

        try {

            CadesBESParameters params;
            if (signingBean.getTspURL() != null) {
                params = new CadesTParameters(signingBean.getTspURL(), null, null);
                params.addContentTimestampProps(signingBean.getTspURL(), null, null);
            } else {
                params = new CadesBESParameters();
            }
            if (signingBean.getDigestAlgorithm() != null) {
                params.setDigestAlgorithm(signingBean.getDigestAlgorithm().getAlgId().getImplementationName());
            }
            if (signingBean.getSignatureAlgorithm() != null) {
                params.setSignatureAlgorithm(signingBean.getSignatureAlgorithm().getAlgId().getImplementationName());
            }
            X509Certificate [] signer = new X509Certificate[1];
            signer[0] = signingBean.getKeyStoreBean().getSelectedCert();
            int mode = signingBean.getSigningMode().getMode();
            CadesSignatureStream signatureStream = new CadesSignatureStream(signingBean.getDataIN(), mode);
            signatureStream.addSignerInfo(signingBean.getKeyStoreBean().getSelectedKey(),
                    signer, params);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            signatureStream.encodeSignature(out);
            ByteArrayInputStream  in = new ByteArrayInputStream(out.toByteArray());
            InputStreamDataSource ds = new InputStreamDataSource(in);
            return ds;
        } catch (Exception e) {
            throw new IllegalStateException("error occured", e);
        }
    }

    public DataSource encryptAndSign(SigningBean bean) {
        this.encryptCMS(bean);
        return this.signCMS(bean);
    }

    /**
     * This method signes data with a classic CM signature either IMPLICIT or EXPLICIT
     * @param signingBean the bean containing the parameters
     * @return the data-source containing the signature
     * @throws CodingException error case
     * @throws NoSuchAlgorithmException error case
     * @throws IOException error case
     * @throws CMSException error case
     * @throws CertificateException error case
     */
    private InputStreamDataSource getInputStreamSigDataSource(SigningBean signingBean)
            throws CodingException, NoSuchAlgorithmException, IOException, CMSException, CertificateException {
        X509Certificate selectedCert = signingBean.getKeyStoreBean().getSelectedCert();
        PrivateKey selectedKey = signingBean.getKeyStoreBean().getSelectedKey();
        InputStream dataStream;
        if (signingBean.getDataSource() != null) {
            dataStream = signingBean.getDataSource().getInputStream();
        } else {
            dataStream = signingBean.getDataIN();
        }
        int mode = signingBean.getSigningMode().getMode();
        SignedDataStream stream = new SignedDataStream(dataStream, mode);
        X509Certificate [] certChain = new X509Certificate[1];
        certChain[0] = selectedCert;
        stream.setCertificates(certChain);
        AlgorithmID digestAlgorithm = null;
        AlgorithmID signatureAlgorithm = null;
        if (signingBean.getDigestAlgorithm() != null) {
            DigestAlg alg = signingBean.getDigestAlgorithm();
            digestAlgorithm = alg.getAlgId();
        }
        if (signingBean.getSignatureAlgorithm() != null) {
            SignatureAlg alg = signingBean.getSignatureAlgorithm();
            signatureAlgorithm = alg.getAlgId();
        }
        SignerInfo signerInfo = new SignerInfo(selectedCert,
                digestAlgorithm,
                signatureAlgorithm,
                selectedKey);
        AlgorithmID sigAlg = signerInfo.getSignatureAlgorithm();
        if (selectedKey.getAlgorithm().contains("EC")) {
            sigAlg.encodeAbsentParametersAsNull(true);
        }
        SigningTime signingTime = new SigningTime();
        Attribute [] attributes = new Attribute[3];
        SigningCertificate signingCertificate = new SigningCertificate(certChain);
        CMSContentType contentType = new CMSContentType(ObjectID.cms_data);
        attributes[0] = new Attribute(contentType);
        attributes[1] = new Attribute(signingTime);
        attributes[2] = new Attribute(signingCertificate);
        signerInfo.setSignedAttributes(attributes);
        stream.addSignerInfo(signerInfo);
        stream.setBlockSize(2048);
        if (mode == SignedDataStream.EXPLICIT) {
            InputStream data_is = stream.getInputStream();
            eatStream(data_is);
        }
        // create the ContentInfo
        ContentInfoStream cis = new ContentInfoStream(stream);
        // return the SignedData as encoded byte array with block size 2048
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        cis.writeTo(os);

        InputStream result = new ByteArrayInputStream(os.toByteArray());
        return new InputStreamDataSource(result);
    }

    /**
     * This method encrypts a message using the CMS encryption
     * @param bean the signing bean holding the needed parameters
     * @return the encrypted stream
     */
    public DataSource encryptCMS(SigningBean bean) {

        EncryptedDataStream encrypted_data;
        try {
            encrypted_data = new EncryptedDataStream(bean.getDataIN(), 2048);
            AlgorithmID pbeAlg = (AlgorithmID) bean.getCryptoAlgorithm().getAlgId().clone();
            System.out.println(pbeAlg.getImplementationName());
            encrypted_data.setupCipher(pbeAlg,
                    bean.getDecryptPWD().toCharArray());
        } catch (InvalidKeyException ex) {
            throw new IllegalStateException("Key error: " + ex.toString());
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Content encryption algorithm not implemented: " + ex.toString());
        }
        try {
            // wrap into ContentInfo and encode
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            ContentInfoStream cis = new ContentInfoStream(encrypted_data);
            cis.writeTo(os);

            InputStream result = new ByteArrayInputStream(os.toByteArray());
            InputStreamDataSource ds = new InputStreamDataSource(result);
            bean.setDataSource(ds);
            return ds;
        } catch (CMSException | IOException e) {
            throw new IllegalStateException("error occured", e);

        }
    }


    /**
     * This method decrypts a encrypted CMS message
     * @param encodedStream the encrypted stream
     * @return the datasource with the decrypt data
     */
    public DataSource decryptCMS(InputStream encodedStream)  {
        try{
            ContentInfoStream cis = new ContentInfoStream(encodedStream);

            EncryptedDataStream encrypted_data = (EncryptedDataStream)cis.getContent();

            System.out.println("Information about the encrypted data:");
            EncryptedContentInfoStream eci = encrypted_data.getEncryptedContentInfo();
            System.out.println("Content type: "+eci.getContentType().getName());
            System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

            // decrypt the message

                encrypted_data.setupCipher(properties.getDecryptPWD().toCharArray());
                InputStream decrypted = encrypted_data.getInputStream();

                InputStreamDataSource ds = new InputStreamDataSource(decrypted);
                return ds;
        } catch (IOException | CMSParsingException ex) {
            throw new IllegalStateException("I/O", ex);
        } catch (InvalidKeyException ex) {
            throw new IllegalStateException("Key error: "+ex.toString());
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Content encryption algorithm not implemented: "+ex.getMessage());
        } catch (InvalidAlgorithmParameterException ex) {
            throw new IllegalStateException("Invalid Parameters: "+ex.getMessage());
        } catch (InvalidParameterSpecException ex) {
            throw new IllegalStateException("Invalid Parameters: " + ex.getMessage());
        }

    }

    /**
     * This method skips a input stream
     * @param data_is the stream
     */
    public static void eatStream(InputStream data_is) {

        byte[] buf = new byte[2048];
            int r;
            while (true) {
                try {
                    if (!((r = data_is.read(buf)) > 0)) break;
                } catch (IOException e) {
                    e.printStackTrace();
                }
                ;   // skip data
            }
     }

    /**
     * Writes the datasource to a file
     * @param ds the datasource which is written
     * @param bean
     */
     public void writeToFile(DataSource ds, SigningBean bean) {
        try {
            File outFile = new File(bean.getOutputPath()).getAbsoluteFile();
            FileOutputStream out = new FileOutputStream(outFile);
            InputStream stream = ds.getInputStream();
            byte[] buffer = new byte[2048];
            int bytesRead;
            while ((bytesRead = stream.read(buffer)) > 0) {
                out.write(buffer, 0, bytesRead);
            }
            stream.close();
            out.close();
        } catch (IOException e) {
            throw new IllegalStateException("faild to write output");
        }
     }

    public DataSource signEncrCMS(SigningBean signingBean) {
        try {
            SignedData signedData = new SignedData(signingBean.getCertIN());
            if (signedData.getMode() == SignedData.EXPLICIT) {
                throw new IllegalStateException("cannit handle explicit stream");
            }

            PrivateKey privKey = null;
            X509Certificate signerCert = null;
            byte[] certData = signedData.getContent();
            if (certData != null && certData.length > 0) {
                signerCert = new X509Certificate(certData);
                if (signerCert != null) {
                    System.out.println("cert found: " + signerCert.toString());
                    PrivateKeyStore store = new PrivateKeyStore(properties,true);
                    privKey = store.getPrivateKey(signingBean.getSignedWithAlias());
                } else {
                    throw new IllegalStateException("no input data found");
                }
            } else {
                throw new IllegalStateException("no input data found");
            }
            boolean found = false;
            if(privKey != null) {
                SignerInfo [] infos = signedData.getSignerInfos();
                X509Certificate selectedCert = signingBean.getKeyStoreBean().getSelectedCert();
                SignerInfo dummy = signedData.getSignerInfo(selectedCert);
                if (infos != null && infos.length >= 1) {
                    for (SignerInfo info: infos) {
                        if (info.isSignerCertificate(selectedCert)) {
                            found = true;
                        }
                    }
                } else {
                    throw new IllegalStateException("no input data found");
                }
                if (privKey != null &&  found && signerCert != null) {
                    DataSource ds = getInputStreamSigDataSource(signingBean);
                    return ds;
                } else {
                    throw new IllegalStateException("no input data found");
                }
            } else {
                throw new IllegalStateException("no input data found");
            }
        } catch (Exception ex) {
            throw new IllegalStateException("Cannot read certificate", ex);
        }
    }


    /**
     * Creates a CMS <code>EnvelopedData</code> message and wraps it into a ContentInfo.
     * <p>
     *
     * @param data the message to be enveloped, as byte representation
     * @return the DER encoded ContentInfo holding the EnvelopedData object just created
     */
    public DataSource envelopeDataCMS(InputStream data)  {

        EnvelopedDataStream enveloped_data;

        // create a new EnvelopedData object encrypted with TripleDES CBC
        try {

            AlgorithmID pbeAlgorithm = AlgorithmID.getAlgorithmID(properties.getEnvelopAlg());
            enveloped_data = new EnvelopedDataStream(data, pbeAlgorithm);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("No implementation for Triple-DES-CBC.");
        }

        // create the recipient infos
        RecipientInfo[] recipients = new RecipientInfo[1];
        // user1 is the first receiver
        recipients[0] = new KeyTransRecipientInfo(keyStoreBean.getSelectedCert(), (AlgorithmID)AlgorithmID.rsaEncryption.clone());

        // specify the recipients of the encrypted message
        enveloped_data.setRecipientInfos(recipients);
// wrap into ContentInfo and encode
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        // wrap into contentInfo
        ContentInfoStream cis = new ContentInfoStream(enveloped_data);
        try {
            cis.writeTo(os);
        } catch(IOException | CMSException e) {
            throw new IllegalStateException("could not write result", e);
        }

        InputStream result = new ByteArrayInputStream(os.toByteArray());
        InputStreamDataSource ds = new InputStreamDataSource(result);
        return ds;
        // return the EnvelopedDate as DER encoded byte array

    }

    /**
     * Decrypts the encrypted content of the given <code>EnvelopedData</code> object for the
     * specified recipient and returns the decrypted (= original) message.
     *
     * @param encoding the DER encoded ContentInfo holding an EnvelopedData
     *

     *
     * @return the recovered message, as byte array
     */
    public DataSource getEnvelopedData(InputStream encoding) {
        EnvelopedDataStream enveloped_data = null;

        try {
            ContentInfoStream cis = new ContentInfoStream(encoding);
            enveloped_data = (EnvelopedDataStream) cis.getContent();
        } catch(Exception e) {
            throw new IllegalStateException("could not generate contenmt-info", e);
        }

        System.out.println("Information about the encrypted data:");
        EncryptedContentInfoStream eciS = (EncryptedContentInfoStream)enveloped_data.getEncryptedContentInfo();
        System.out.println("Content type: "+eciS.getContentType().getName());
        System.out.println("Content encryption algorithm: "+eciS.getContentEncryptionAlgorithm().getName());

        System.out.println("\nThis message can be decrypted by the owners of the following certificates:");

// decrypt the message
        try {
            enveloped_data.setupCipher(keyStoreBean.getSelectedKey(), 0);
            InputStreamDataSource ds = new InputStreamDataSource(enveloped_data.getInputStream());
            return ds;

        } catch (InvalidKeyException ex) {
            throw new IllegalStateException("Private key error: ",ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Content encryption algorithm not implemented: ",ex);
        } catch (CMSException ex) {
            throw new IllegalStateException("general error: ",ex);
        }
    }


        public static SigningUtil.Builder newBuilder() {
        return new SigningUtil.Builder();
     }



    public static class Builder {

        private SigningUtil myInstance = null;
        public Builder() {
            myInstance = new SigningUtil();
        }

        public Builder withKeystoreBean(CertWriterReader.KeyStoreBean bean) {
            myInstance.keyStoreBean = bean;
            return this;
        }

        public Builder withProperties(ConfigReader.MainProperties props) {
            myInstance.properties = props;
            return this;
        }

        public Builder withMode(int mode) {
            myInstance.mode = mode;
            return this;
        }

        public Builder withSignaturePath(String path) {
            myInstance.signaturePath = path;
            return this;
        }

        public SigningUtil build() {
            return myInstance;
        }
    }

    public static class InputStreamDataSource implements DataSource {

        private final InputStream myStream;

        public InputStreamDataSource(InputStream in) {
            myStream = in;
        }

        public InputStream getInputStream() throws IOException {
            return myStream;
        }

        public OutputStream getOutputStream() throws IOException {
            return null;
        }

        public String getContentType() {
            return "application/cms";
        }

        public String getName() {
            return "CMSSig";
        }
    }
}
