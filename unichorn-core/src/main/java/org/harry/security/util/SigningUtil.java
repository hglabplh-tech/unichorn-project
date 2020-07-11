package org.harry.security.util;

import iaik.asn1.CodingException;
import iaik.asn1.DerInputException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.*;
import iaik.cms.attributes.CMSContentType;
import iaik.cms.attributes.CounterSignature;
import iaik.cms.attributes.SigningTime;
import iaik.pdf.asn1objects.ArchiveTimeStampv3;
import iaik.pdf.cmscades.CadesSignatureStream;
import iaik.pdf.parameters.CadesBESParameters;
import iaik.pdf.parameters.CadesLTAParameters;
import iaik.pdf.parameters.CadesTParameters;
import iaik.security.cipher.PBEKey;
import iaik.smime.ess.SigningCertificate;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.OCSPResponse;
import iaik.x509.ocsp.ReqCert;
import org.apache.commons.io.IOUtils;
import org.harry.security.util.algoritms.CryptoAlg;
import org.harry.security.util.algoritms.DigestAlg;
import org.harry.security.util.algoritms.SignatureAlg;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.ocsp.HttpOCSPClient;
import org.harry.security.util.ocsp.OCSPCRLClient;
import org.pmw.tinylog.Logger;

import javax.activation.DataSource;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidParameterSpecException;

import static org.harry.security.CommonConst.OCSP_URL;

public class SigningUtil {


    public SigningUtil() {

    }

    /**
     * singns CMS
     *
     * @param signingBean the parameters
     * @return the data-source with the signature
     */
    public DataSource signCMS(SigningBean signingBean) {

        try {


            InputStreamDataSource ds = getInputStreamSigDataSource(signingBean);
            return ds;
        } catch (Exception e) {
            Logger.trace("Signing error -> " + e.getMessage());
            throw new IllegalStateException("error occured", e);
        }


    }

    /**
     * The method signs content with a well defined CAdES signature possibly containing time-stamps
     *
     * @param signingBean the bean containing the parameters
     * @return the data source containing the signature
     */
    public DataSource signCAdES(SigningBean signingBean, boolean upgradeSig) {

        try {

            CadesBESParameters params;
            Logger.trace("set tsa parameters " + signingBean.getTspURL());
            if (signingBean.getTspURL() != null) {
                Logger.trace("really set the parameters");
                params = new CadesTParameters(signingBean.getTspURL(), null, null);
                Logger.trace("set second parameter");
                params.addContentTimestampProps(signingBean.getTspURL(), null, null);
                Logger.trace("really set the params success");
            } else {
                Logger.trace("set nothing ");
                params = new CadesBESParameters();

            }
            Logger.trace("set digest algorithm parameters");
            if (signingBean.getDigestAlgorithm() != null) {
                params.setDigestAlgorithm(signingBean.getDigestAlgorithm().getAlgId().getImplementationName());
            }
            Logger.trace("set signature algorithm parameters");
            if (signingBean.getSignatureAlgorithm() != null) {
                params.setSignatureAlgorithm(signingBean.getSignatureAlgorithm().getAlgId().getImplementationName());
            }
            Logger.trace("get store bean");
            X509Certificate[] signer = new X509Certificate[1];
            signer = signingBean.getKeyStoreBean().getChain();
            int mode = signingBean.getSigningMode().getMode();

            InputStream stream = signingBean.getDataIN();
            Logger.trace("Create signature Stream");
            CadesSignatureStream signatureStream = new CadesSignatureStream(stream, mode);
            SignedDataStream signedData = signatureStream.getSignedDataObject();
            CertificateSet certSet = new CertificateSet();
            addCertificates(signingBean, signer, certSet);
            signatureStream.addSignerInfo(signingBean.getKeyStoreBean().getSelectedKey(),
                    signer, params);
            signedData.setCertificateSet(certSet);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Logger.trace("Encode signature Stream");
            if (signingBean.getTspURL() != null && !signingBean.getTspURL().isEmpty()) {
                signedData.setSDSEncodeListener(new TimeStampListener(signingBean.getTspURL()));
            }
            signatureStream.encodeSignature(out);
            ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
            DataSource ds = new InputStreamDataSource(in);
            stream.close();
            out.close();
            if (upgradeSig) {
                ds = upgradeSignature(signingBean, ds);
            }
            return ds;
        } catch (Exception ex) {
            Logger.trace("Error happened " + ex.getMessage() + " type " + ex.getClass().getCanonicalName());
            throw new IllegalStateException("error occured", ex);
        }
    }

    /**
     * Upgrade the signature with LTV data OCSP responses and timestamps for archiving
     *
     * @param signingBean the signing bean
     * @param ds          the input data-source
     * @return the updated PDF
     * @throws NoSuchAlgorithmException error case
     */
    public DataSource upgradeSignature(SigningBean signingBean, DataSource ds) throws NoSuchAlgorithmException {
        ByteArrayOutputStream archivedSignatureStream;
        archivedSignatureStream = new ByteArrayOutputStream();
        String archiveTimestampDigestAlgorithm = ArchiveTimeStampv3.DEFAULTHASHALGORITHM.getJcaStandardName();
        try {
            Logger.trace("upgrade with archTimeStamp Algorithm:" + archiveTimestampDigestAlgorithm);
            InputStream data = signingBean.getDataINFile();
            CadesSignatureStream cadesSig = new CadesSignatureStream(ds.getInputStream(), data,
                    new String[]{archiveTimestampDigestAlgorithm}, archivedSignatureStream);
            Logger.trace("Before verifying signature");
            cadesSig.verifySignatureValue(signingBean.getKeyStoreBean().getSelectedCert());
            Logger.trace("Verifying signature succeded");
            CadesLTAParameters parameters = new CadesLTAParameters(signingBean.getTspURL(),
                    null, null);

            X509Certificate[] cert = signingBean.getKeyStoreBean().getChain();
            String url = OCSPCRLClient.getOCSPUrl(signingBean.getKeyStoreBean().getSelectedCert());
            if (url == null) {
                url = OCSP_URL;
            }
            Logger.trace("Get OCSP values from URL: " + url);
            OCSPResponse response = HttpOCSPClient.sendOCSPRequest(url, null, null,
                    cert, ReqCert.certID, false, true);
            OCSPResponse[] responses = new OCSPResponse[1];
            responses[0] = response;
            parameters.addArchiveDetails(cert, null, responses);
            Logger.trace("Get OCSP values  succeded");
            Logger.trace("add archive timestamp");
            SubjectKeyID identifier = new SubjectKeyID(cert[0]);
            cadesSig.addArchiveTimeStamp(0, parameters);
            Logger.trace("encode upgraded");
            cadesSig.encodeUpgradedSignature();
            Logger.trace("encode upgraded succeded");
            ByteArrayInputStream in = new ByteArrayInputStream(archivedSignatureStream.toByteArray());
            InputStreamDataSource dsResult = new InputStreamDataSource(in);
            return dsResult;
        } catch (Exception ex) {
            Logger.trace("Error occurred: " + ex.getMessage() + " type: " + ex.getClass().getCanonicalName());
            Logger.trace(ex);
            throw new IllegalStateException("signing failed", ex);
        }
    }

    /**
     * Encrypt data and sign it immediately afterwards
     *
     * @param bean the signing bean with the input data
     * @return the data sources from encryption and signing
     */
    public Tuple<DataSource, DataSource> encryptAndSign(SigningBean bean) {
        try {
            CopyInputStreamDataSource copySource = new CopyInputStreamDataSource(bean.getDataIN());
            bean = bean.setDataIN(copySource.getInputStream());

            DataSource result = this.encryptCMS(bean);
            CopyInputStreamDataSource copyResult = new CopyInputStreamDataSource(result.getInputStream());
            bean = bean.setDataIN(result.getInputStream());
            return new Tuple<>(copyResult, this.signCMS(bean));
        } catch (IOException ex) {
            throw new IllegalStateException("signing and encryption failed", ex);
        }
    }

    /**
     * This method signes data with a classic CM signature either IMPLICIT or EXPLICIT
     *
     * @param signingBean the bean containing the parameters
     * @return the data-source containing the signature
     * @throws CodingException          error case
     * @throws NoSuchAlgorithmException error case
     * @throws IOException              error case
     * @throws CMSException             error case
     * @throws CertificateException     error case
     */
    private InputStreamDataSource getInputStreamSigDataSource(SigningBean signingBean)
            throws CodingException, NoSuchAlgorithmException, IOException, CMSException,
            CertificateException, SignatureException {
        try {

            X509Certificate[] chain = signingBean.getKeyStoreBean().getChain();
            PrivateKey selectedKey = signingBean.getKeyStoreBean().getSelectedKey();
            InputStream dataStream;
            if (signingBean.getDataSource() != null) {
                Logger.trace("Data selected from data source");
                dataStream = signingBean.getDataSource().getInputStream();
            } else {
                Logger.trace("Data selected from dataIN");
                dataStream = signingBean.getDataIN();
            }
            Logger.trace("create signing stream");
            int mode = signingBean.getSigningMode().getMode();
            SignedDataStream stream = new SignedDataStream(dataStream, mode);
            CertificateSet certSet = new CertificateSet();
            addCertificates(signingBean, chain, certSet);
            stream.setCertificateSet(certSet);
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
            Logger.trace("Create signer info");
            SignerInfo signerInfo = new SignerInfo(chain[0],
                    digestAlgorithm,
                    signatureAlgorithm,
                    selectedKey);
            AlgorithmID sigAlg = signerInfo.getSignatureAlgorithm();
            if (selectedKey.getAlgorithm().contains("EC")) {
                sigAlg.encodeAbsentParametersAsNull(true);
            }
            Logger.trace("Set content attributes");
            SigningTime signingTime = new SigningTime();
            Attribute[] attributes = new Attribute[3];
            SigningCertificate signingCertificate = new SigningCertificate(chain);
            CMSContentType contentType = new CMSContentType(ObjectID.cms_data);
            attributes[0] = new Attribute(contentType);
            attributes[1] = new Attribute(signingTime);
            attributes[2] = new Attribute(signingCertificate);

            signerInfo.setSignedAttributes(attributes);
            Logger.trace("Add signer info to signature");
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

            Logger.trace("Really sign the thing");
            cis.writeTo(os);
            Logger.trace("Really signed the thing");
            InputStream result = new ByteArrayInputStream(os.toByteArray());
            return new InputStreamDataSource(result);
        } catch (Exception ex) {
            Logger.trace("error signing data" + ex.getMessage());
            Logger.trace(ex);
            throw new IllegalStateException("error signing data", ex);
        }
    }

    /**
     * This method sets a counter signature to a given signature
     * @param signingBean the data needed for setting a counter signature
     * @return the counter signed stuff
     */
    public DataSource setCounterSignature(SigningBean signingBean) {
        try {
            // set counter signature
            InputStream stream = signingBean.getDataIN();
            ContentInfoStream cis = new ContentInfoStream(stream);
            ObjectID contentType = cis.getContentType();
            // ok we have a signature lets have a look
            System.out.println("object id: --> " + contentType.toString());
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            SignedDataStream signedData = new SignedDataStream(cis.getContentInputStream());
            if (signedData.getMode() == SignedData.EXPLICIT) {
                if (signingBean.getDataINFile() == null) {
                    throw new IllegalStateException("data stream is null though signature is explicit");
                }
                signedData.setInputStream(signingBean.getDataINFile());
            }
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
            //  signedData.verify(0);
            Attribute[] attributes = new Attribute[1];
            CounterSignature counterSig = new CounterSignature(
                    new IssuerAndSerialNumber(signingBean.getCounterKeyStoreBean().getSelectedCert()),
                    digestAlgorithm,
                    signatureAlgorithm,
                    signingBean.getCounterKeyStoreBean().getSelectedKey()
            );
            SignerInfo signerInfo = signedData.getSignerInfos()[0];
            counterSig.counterSign(signerInfo);
            Attribute attr = new Attribute(counterSig);
            attributes[0] = attr;
            signerInfo.setUnsignedAttributes(attributes);
            signedData.setBlockSize(2048);
            int mode = signingBean.getSigningMode().getMode();
            if (mode == SignedDataStream.EXPLICIT) {
                InputStream data_is = signedData.getInputStream();
                eatStream(data_is);
            }

            // create the ContentInfo
            cis = new ContentInfoStream(signedData);
            // return the SignedData as encoded byte array with block size 2048
            ByteArrayOutputStream os = new ByteArrayOutputStream();

            Logger.trace("Really sign the thing");
            cis.writeTo(os);
            Logger.trace("Really signed the thing");
            InputStream result = new ByteArrayInputStream(os.toByteArray());
            return new InputStreamDataSource(result);
        } catch (Exception ex) {
            Logger.trace("error occurred during set counter signature: " + ex.getMessage());
            Logger.trace(ex);
            throw new IllegalStateException("error occurred during set counter signature", ex);
        }
    }


    /**
     * Initialize the certificate set for a signature
     * @param signingBean the signingbean
     * @param chain the certificate chain
     * @param certSet the certificate set
     */
    private void addCertificates(SigningBean signingBean, X509Certificate[] chain, CertificateSet certSet) {
        if (signingBean.getAttributeCertificate() != null) {
            CertificateChoices choices = new CertificateChoices(signingBean.getAttributeCertificate());
            certSet.addCertificateChoices(choices);
        }
        for(X509Certificate candidate: chain) {
            CertificateChoices choices = new CertificateChoices(candidate);
            certSet.addCertificateChoices(choices);
        }
    }

    /**
     * check na signature for correctness and give back the signed data
     * @param signature the signature containing the data if IMPLICIT
     * @param data the data given for EXPLICIT mode
     * @return the data as data-source
     * @throws IOException error case
     * @throws CMSParsingException error case
     */
    public DataSource unpackSignature(InputStream signature, InputStream data) throws IOException, CMSParsingException {
        boolean success = false;
        ContentInfoStream cis = new ContentInfoStream(signature);
        CopyInputStreamDataSource copySource = new CopyInputStreamDataSource(data);
        try {
            SignedData signedData;
            if (data != null) {
                signedData = new SignedData(cis.getContentInputStream());
            } else {
                signedData = new SignedData(cis.getContentInputStream());
            }
            if (signedData.getMode() == SignedDataStream.EXPLICIT) {
                // explicitly signed; set the content received by other means
                signedData.setInputStream(copySource.getInputStream());
            }


            SignerInfo[] signerInfos;
            signerInfos = signedData.getSignerInfos();
            X509Certificate [] possibleSigners = signedData.getX509Certificates();
            X509Certificate signer = null;
            //SigningUtil.eatStream(signedData.getInputStream());
            for (SignerInfo info : signerInfos) {
                info.setSecurityProvider(new IaikCCProvider());
                for (X509Certificate actual:possibleSigners) {
                    if(info.isSignerCertificate(actual)) {
                        signer = actual;
                        break;
                    }
                }
                if (signer != null) {
                    //info.verifySignature(signer.getPublicKey());
                }
            }
            byte [] content = signedData.getContent();
            InputStream input = new ByteArrayInputStream(content);
            return new InputStreamDataSource(input);
        } catch (Exception ex) {
            throw new IllegalStateException("quick check failed", ex);
        }
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
     * @param bean the encrypted data
     * @return the datasource with the decrypt data
     */
    public DataSource decryptCMS(SigningBean bean)  {
        try{
            ContentInfoStream cis = new ContentInfoStream(bean.getDataIN());

            EncryptedDataStream encrypted_data = (EncryptedDataStream)cis.getContent();

            System.out.println("Information about the encrypted data:");
            EncryptedContentInfoStream eci = encrypted_data.getEncryptedContentInfo();
            System.out.println("Content type: "+eci.getContentType().getName());
            System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

            // decrypt the message

                encrypted_data.setupCipher(bean.getDecryptPWD().toCharArray());
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
     * This method encrypts a string message using the CMS encryption
     * @param toEncrypt the String which has to be encrypted
     * @param masterPW the master password used for encryption
     * @return the encrypted stream as base64 String
     */
    public String encryptBase64CMS(String toEncrypt, String masterPW) {

        EncryptedData encrypted_data;
        try {
            encrypted_data = new EncryptedData(toEncrypt.getBytes());
            AlgorithmID pbeAlg = CryptoAlg.PBE_SHAA3_KEY_TRIPLE_DES_CBC.getAlgId();
            System.out.println(pbeAlg.getImplementationName());
            encrypted_data.setupCipher(pbeAlg, masterPW.toCharArray());
        } catch (InvalidKeyException ex) {
            throw new IllegalStateException("Key error: " + ex.toString());
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Content encryption algorithm not implemented: " + ex.toString());
        }
        try {
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            ContentInfoStream cis = new ContentInfoStream(encrypted_data);
            cis.writeTo(result);
            String base64 = Util.toBase64String(result.toByteArray());
            return base64;
        } catch (Exception ex) {
            throw new IllegalStateException("error occured", ex);

        }
    }

    /**
     * This method encrypts a string message using the CMS encryption
     * @param toEncrypt the String which has to be encrypted
     * @param masterPW the master password used for encryption
     * @return the encrypted stream as base64 String
     */
    public DataSource encryptStrongBase64CMS(String toEncrypt, String masterPW) {

        EncryptedData encrypted_data;
        try {
            encrypted_data = new EncryptedData(toEncrypt.getBytes());
            AlgorithmID pbeAlg = CryptoAlg.PBE_SHAA3_KEY_TRIPLE_DES_CBC.getAlgId();
            System.out.println(pbeAlg.getImplementationName());
            encrypted_data.setupCipher(pbeAlg, masterPW.toCharArray());
        } catch (InvalidKeyException ex) {
            throw new IllegalStateException("Key error: " + ex.toString());
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Content encryption algorithm not implemented: " + ex.toString());
        }
        try {
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            ContentInfoStream cis = new ContentInfoStream(encrypted_data);
            cis.writeTo(result);
            byte[] expanded = getNewPassCode(toEncrypt, masterPW);
            encrypted_data = new EncryptedData(result.toByteArray());
            AlgorithmID pbeAlg = CryptoAlg.PBE_SHAA3_KEY_TRIPLE_DES_CBC.getAlgId();
            System.out.println(pbeAlg.getImplementationName());
            encrypted_data.setupCipher(pbeAlg, new String(expanded).toCharArray());
            result = new ByteArrayOutputStream();
            cis = new ContentInfoStream(encrypted_data);
            cis.writeTo(result);
            InputStream input = new ByteArrayInputStream(result.toByteArray());
            InputStreamDataSource ds = new InputStreamDataSource(input);
            return ds;
        } catch (Exception ex) {
            throw new IllegalStateException("error occured", ex);

        }
    }

    private byte[] getNewPassCode(String toEncrypt, String masterPW) {
        byte[] expanded = new byte[toEncrypt.getBytes().length + masterPW.getBytes().length];
        System.arraycopy(toEncrypt.getBytes(), 0, expanded, 0, toEncrypt.getBytes().length);
        System.arraycopy(masterPW.getBytes(), 0, expanded, toEncrypt.getBytes().length, masterPW.getBytes().length);
        return expanded;
    }

    /**
     * This method encrypts a string message using the CMS encryption
     * @param encrypted the stream which has to be decrypted
     * @param masterPW the master password used for encryption
     * @return the encrypted stream as base64 String
     */
    public String decryptStrongBase64CMS(InputStream encrypted, String passwd, String masterPW) {

        EncryptedData encrypted_data;
        try {
            ContentInfoStream cis = new ContentInfoStream(encrypted);
            byte[] expanded = getNewPassCode(passwd, masterPW);
            encrypted_data = new EncryptedData(cis.getContentInputStream());
            encrypted_data.setupCipher(new String(expanded).toCharArray());
        } catch (InvalidKeyException ex) {
            throw new IllegalStateException("Key error: " + ex.toString());
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidParameterSpecException | IOException | CMSParsingException ex) {
            throw new IllegalStateException("Content encryption algorithm not implemented: " + ex.toString());
        }
        try {
            byte[] decrypted = encrypted_data.getContent();
            ByteArrayInputStream stream = new ByteArrayInputStream(decrypted);
            ContentInfoStream cis = new ContentInfoStream(stream);
            byte[] expanded = getNewPassCode(passwd, masterPW);
            encrypted_data = new EncryptedData(cis.getContentInputStream());
            encrypted_data.setupCipher(masterPW.toCharArray());
            decrypted = encrypted_data.getContent();
            return new String(decrypted);
        } catch (Exception ex) {
            throw new IllegalStateException("error occured", ex);

        }
    }





    /**
     * This method decrypts a encrypted CMS message
     * @param base64 the encrypted data as base 64 string
     * @param masterPW master password to decrypt data
     * @return the decoded plain String
     */
    public String decryptBase64CMS(String base64, String masterPW)  {
        try{
            byte[] decodedBase64 = Util.fromBase64String(base64);

            ByteArrayInputStream input = new ByteArrayInputStream(decodedBase64);
            ContentInfo cis = new ContentInfo(input);
            EncryptedData encrypted_data = (EncryptedData)cis.getContent();

            System.out.println("Information about the encrypted data:");
            EncryptedContentInfoStream eci = encrypted_data.getEncryptedContentInfo();
            System.out.println("Content type: "+eci.getContentType().getName());
            System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());
            // decrypt the message

            encrypted_data.setupCipher(masterPW.toCharArray());
            byte[] decrypted = encrypted_data.getContent();

            return new String(decrypted);
        } catch (Exception ex) {
            throw new IllegalStateException("I/O", ex);
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
     * @param bean the signing bean
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
            out.flush();
            stream.close();
            out.close();
        } catch (IOException e) {
            throw new IllegalStateException("failed to write output" + e.getMessage(), e);
        }
     }

    /**
     * sign a certificate
     * @param signingBean the signing bean
     * @return the signed data
     */
    public DataSource signEncrCMS(SigningBean signingBean) {
        ConfigReader.MainProperties properties = ConfigReader.loadStore();
        try {
            SignedData signedData = new SignedData(signingBean.getCertIN());
            if (signedData.getMode() == SignedData.EXPLICIT) {
                throw new IllegalStateException("cannot handle explicit stream");
            }

            PrivateKey privKey = null;
            X509Certificate signerCert = null;
            byte[] certData = signedData.getContent();
            if (certData != null && certData.length > 0) {
                signerCert = new X509Certificate(certData);
                if (signerCert != null) {
                    System.out.println("cert found: " + signerCert.toString());
                    KeyStore store = KeyStoreTool.loadStore(
                            new FileInputStream(properties.getKeystorePath()),
                            properties.getKeystorePass().toCharArray(), "UnicP12");
                    privKey = (PrivateKey)store.
                            getKey(signingBean.getSignedWithAlias(),
                                    properties.getKeystorePass().toCharArray());
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
    public DataSource envelopeDataCMS(SigningBean bean, InputStream data)  {

        EnvelopedDataStream enveloped_data;

        // create a new EnvelopedData object encrypted with TripleDES CBC
        try {
            ConfigReader.MainProperties properties = ConfigReader.loadStore();
            AlgorithmID pbeAlgorithm = AlgorithmID.getAlgorithmID(properties.getEnvelopAlg());
            enveloped_data = new EnvelopedDataStream(data, pbeAlgorithm);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("No implementation for Triple-DES-CBC.");
        }

        // create the recipient infos
        RecipientInfo[] recipients = new RecipientInfo[1];
        // user1 is the first receiver
        recipients[0] = new KeyTransRecipientInfo(bean.getKeyStoreBean().getSelectedCert(), (AlgorithmID)AlgorithmID.rsaEncryption.clone());

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
    public DataSource getEnvelopedData(SigningBean bean, InputStream encoding) {
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
            enveloped_data.setupCipher(bean.getKeyStoreBean().getSelectedKey(), 0);
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

    public byte[] encryptCiphered(byte[] data, String password)
            throws Exception
    {

        // create a KeySpec from our password
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
        // use the "PKCS#5" or "PBE" SecretKeyFactory to convert the password
        SecretKeyFactory kf = SecretKeyFactory.getInstance("PKCS#5", "IAIK");
        // create an appropriate PbeKey
        PBEKey pbeKey = (PBEKey)kf.generateSecret(keySpec);
        // get the cipher
        Cipher c = Cipher.getInstance("PBES2WithHmacSHA256AndAES", "IAIK");

        // initialize it with PBEKey
        c.init(Cipher.ENCRYPT_MODE, pbeKey);

        // encrypt the data
        byte[] encrypted = c.doFinal(data);

        return encrypted;
    }


    /**
     * A datasource reflecting a pure java.io.InputStream
     */
    public static class InputStreamDataSource implements DataSource {

        /**
         * the used stream
         */
        private final InputStream myStream;

        /**
         * the used stream
         */
        private  String mimeType = null;

        /**
         * CTOr for the datasource
         * @param in the input stream to wrap
         */
        public InputStreamDataSource(InputStream in) {
            myStream = in;
        }

        /**
         * CTOr for the datasource
         * @param in the input stream to wrap
         */
        public InputStreamDataSource(InputStream in, String mimeType) {
            myStream = in;
            this.mimeType = mimeType;
        }



        /**
         * {@inheritDoc}
         */
        @Override
        public InputStream getInputStream() throws IOException {
            return myStream;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public OutputStream getOutputStream() throws IOException {
            return null;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getContentType() {
            if (this.mimeType != null) {
                return mimeType;
            } else {
                return "application/cms";
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getName() {
            return "CMSSig";
        }
    }

    /**
     * A datasource which can be read multiple
     */
    public static class CopyInputStreamDataSource implements DataSource {

        /**
         * the byte array containing the data
         */
        private final byte [] content;


        /**
         * CTOR copying the input stream to a reusable byte-array
         * which is used by get-input-stream to create the returned ByteArrayInputStream
         * @param in the input stream to wrap
         * @throws IOException error case
         */
        public CopyInputStreamDataSource(InputStream in) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            IOUtils.copy(in, out);
            content = out.toByteArray();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public InputStream getInputStream() throws IOException {
            ByteArrayInputStream stream = new ByteArrayInputStream(content);
            return stream;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public OutputStream getOutputStream() throws IOException {
            throw new UnsupportedOperationException("getOutputStream is forbidden");
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getContentType() {
            return "application/cms";
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getName() {
            return "CMSSig";
        }
    }
}
