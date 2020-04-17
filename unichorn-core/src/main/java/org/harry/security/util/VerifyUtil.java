package org.harry.security.util;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.*;
import iaik.pdf.asn1objects.ContentTimeStamp;
import iaik.pdf.asn1objects.SignatureTimeStamp;
import iaik.pdf.cmscades.CadesSignatureStream;
import iaik.pdf.cmscades.CmsCadesException;
import iaik.tsp.TimeStampToken;
import iaik.tsp.TspVerificationException;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.OCSPResponse;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.ocsp.HttpOCSPClient;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.trustlist.TrustListWalkerAndGetter;

import java.io.*;
import java.net.URL;
import java.security.DigestInputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.util.*;

import static org.harry.security.util.HttpsChecker.loadKey;

/**
 * This class is designed to verify CMS signatures checking their mathematical and other validity
 * @author Harald Glab-Plhak
 */
public class VerifyUtil {

    /**
     * This is the list of trust-lists provided by EU to check the path of the signers certificate
     */
    private final List<TrustListWalkerAndGetter> walkers;

    private final SigningBean bean;


    /**
     * The default constructor for verification
     * @param walkers the trust lists
     */
    public VerifyUtil(List<TrustListWalkerAndGetter> walkers, SigningBean bean) {
        this.walkers = walkers;
        this.bean = bean;
    }

    public static boolean quickCheck(InputStream signature, InputStream data) throws IOException, CMSParsingException {
            boolean success = false;

        ContentInfoStream cis = new ContentInfoStream(signature);
            try {
                SignedDataStream signedData;
                if (data != null) {
                    signedData = new SignedDataStream(cis.getContentInputStream());
                } else {
                    signedData = new SignedDataStream(cis.getContentInputStream());
                }
                if (signedData.getMode() == SignedDataStream.EXPLICIT) {
                    // explicitly signed; set the content received by other means
                    signedData.setInputStream(data);
                }

                SignerInfo[] signerInfos;
                signerInfos = signedData.getSignerInfos();
                X509Certificate [] possibleSigners = signedData.getX509Certificates();
                X509Certificate signer = null;
                int index = 0;
                SigningUtil.eatStream(signedData.getInputStream());
                for (SignerInfo info : signerInfos) {
                    info.setSecurityProvider(new IaikCCProvider());
                    for (X509Certificate actual:possibleSigners) {
                        if(info.isSignerCertificate(actual)) {
                            signer = actual;
                            break;
                        }
                    }
                    if (signer != null) {
                        info.verifySignature(signer.getPublicKey());
                        success = true;
                        String[] emails = signer.getEmailAddresses();
                        for (String email: emails){
                            System.out.println("email:" + email);
                        }
                        index++;
                    }
                }
                return success;
            } catch (Exception ex) {
                throw new IllegalStateException("quick check failed", ex);
            }
    }

    /**
     * This method checks the validity of a CMS signature and the consistency of the
     * certificate path
     * @param signature the input stream holding the signature data
     * @param data the optional input if we have a EXPLICIT signature of signed data
     * @return the verification result
     */
    public VerifierResult verifyCMSSignature(InputStream signature, InputStream data) {
        VerifierResult result = null;
        try {
            CadesSignatureStream cadesSig = new CadesSignatureStream(signature, data);

            SignedDataStream signedData = cadesSig.getSignedDataObject();
            if (signedData.getMode() == SignedData.EXPLICIT) {
                if (data == null) {
                    throw new IllegalStateException("data stream is null though signature is explicit");
                }
                signedData.setInputStream(data);
            }
            MessageDigest md = makeMessageDigest(AlgorithmID.sha512);
            InputStream inStream = signedData.getInputStream();
            DigestInputStream digestStream =
                    new DigestInputStream(inStream, md);
            SigningUtil.eatStream(digestStream);
            digestStream.close();
            SignerInfo [] signerInfos;
            signerInfos = signedData.getSignerInfos();
            List<X509Certificate> signCertList =
            findSigners(signedData.getX509Certificates(), signerInfos);
            result = isSuccessOfSigner(signedData, signerInfos, signCertList);
            int index = 0;
            for (X509Certificate out: signCertList) {
                FileOutputStream stream = new FileOutputStream("./certificate(" + index +").pem");
                CertWriterReader writer = new CertWriterReader(out);
                writer.writeToFilePEM(stream);
                index++;
            }
            SignatureTimeStamp[]
            tsp = cadesSig.getSignatureTimeStamps(signCertList.get(0));
            signatureTimestampCheck(tsp);

            ContentTimeStamp[] tspContent = cadesSig.getContentTimeStamps(signCertList.get(0));
            contentTimestampCheck(tspContent);
        } catch (Exception ex) {
            throw new IllegalStateException("cannot verify signature reason is", ex);
        }
        return result;
    }

    /**
     * Check the content timestamp of the signature
     * @param tspContent the content timestamps
     * @throws CmsCadesException error case
     * @throws CertificateNotFoundException error case
     * @throws TspVerificationException error case
     */
    public void contentTimestampCheck(ContentTimeStamp[] tspContent) throws CmsCadesException, CertificateNotFoundException, TspVerificationException {
        if (tspContent != null){
            for (ContentTimeStamp contTsp: tspContent) {
                TimeStampToken token = contTsp.getTimeStampToken();
                token.verifyTimeStampToken();
            }
        }
    }

    /**
     * Check the signature timestamp of the signature
     * @param tsp signature timestamp
     * @throws CmsCadesException error case
     * @throws CertificateNotFoundException error case
     * @throws TspVerificationException error case
     */
    public void signatureTimestampCheck(SignatureTimeStamp[] tsp) throws CmsCadesException, CertificateNotFoundException, TspVerificationException {
        if (tsp != null){
            for (SignatureTimeStamp sigTsp: tsp) {
                TimeStampToken token = sigTsp.getTimeStampToken();
                token.verifyTimeStampToken();
            }
        }
    }

    /**
     * Here the signer is checked
     * @param signedData the signed data / signature
     * @param signerInfos the array of signature infos
     * @param signCertList the certificates list holded by the signature
     * @return the verification result
     * @throws CMSSignatureException error case
     */
    public VerifierResult isSuccessOfSigner(
                                     SignedDataStream signedData,
                                     SignerInfo[] signerInfos,
                                     List<X509Certificate> signCertList) throws CMSSignatureException {
        try {
            VerifierResult vResult = new VerifierResult();
            if (signCertList.size() > 0) {
                for (SignerInfo info : signerInfos) {
                    AlgorithmID sigAlg = info.getSignatureAlgorithm();
                    AlgorithmID digestAlg = info.getDigestAlgorithm();
                    SignerInfoCheckResults results = new SignerInfoCheckResults();
                    results.setInfo(info);
                    results.addSignatureResult("signature algorithm",
                            new Tuple<>(sigAlg.getImplementationName(), Outcome.SUCCESS));
                    results.addSignatureResult("digest algorithm",
                            new Tuple<>(digestAlg.getImplementationName(), Outcome.SUCCESS));
                    for (X509Certificate signCert : signCertList) {
                        if (info.isSignerCertificate(signCert)) {
                            vResult.addSignersInfo(signCert.getSubjectDN().getName(), results);
                            try {
                                if (info.verifySignature(signCert.getPublicKey())) {
                                    results.addSignatureResult(signCert.getSubjectDN().getName(),
                                            new Tuple<>("signature base check succeded", Outcome.SUCCESS));
                                    if (bean.isCheckPathOcsp()) {
                                        detectChain(signCert, results);
                                    } else {
                                        results.addSignatureResult(signCert.getSubjectDN().getName(),
                                                new Tuple<>("path / ocsp check omitted", Outcome.UNDETERMINED));
                                    }
                                } else {
                                    results.addSignatureResult(signCert.getSubjectDN().getName(),
                                            new Tuple<>("signature check failed", Outcome.FAILED));
                                }
                            } catch (Exception ex) {
                                results.addSignatureResult(signCert.getSubjectDN().getName(),
                                        new Tuple<>(ex.getMessage(), Outcome.FAILED));
                            }

                        }
                    }
                }

            }
            return vResult;
        } catch (Exception ex) {
            throw new IllegalStateException("check failed unexpected", ex);
        }
    }

    /**
     * Here the chain is checked for validity and consistency
     * @param signCert the signers certificate
     * @param results the check results object
     */
    public void detectChain(X509Certificate signCert, SignerInfoCheckResults results) {
        results.addSignatureResult(
                signCert.getSubjectDN().getName(), new Tuple<>("signature ok", Outcome.SUCCESS));
        Optional<X509Certificate> certOpt = Optional.empty();
        certOpt = getX509IssuerCertificate(signCert, certOpt);
        if (certOpt.isPresent()) {
            System.out.println("found subject:" + certOpt.get().getSubjectDN().getName());
            X509Certificate[] certArray = new X509Certificate[2];
            certArray[0] = signCert;
            certArray[1] = certOpt.get();
            checkOCSP(results, certArray);
        } else {
            results.addSignatureResult(
                    "", new Tuple<>("signature chain building failed", Outcome.FAILED));
        }
        Optional<X509Certificate> certOptIssuer = Optional.empty();
        certOptIssuer = getX509IssuerCertificate(certOpt.get(), certOptIssuer);
        if (certOptIssuer.isPresent()) {
            System.out.println("found subject:" + certOptIssuer.get().getSubjectDN().getName());
            X509Certificate[] certArray = new X509Certificate[2];
            certArray[0] = certOpt.get();
            certArray[1] = certOptIssuer.get();
            checkOCSP(results, certArray);
        } else {
            results.addSignatureResult(
                    "", new Tuple<>("signature chain building failed", Outcome.FAILED));
        }
    }

    /**
     * retrieve the issuers cedrtificate by searching it in the trust list
     * @param signCert the signers certificate
     * @param certOpt the certificate optional holding the issuer later on
     * @return the optional holding the found cdertificate
     */
    public Optional<X509Certificate> getX509IssuerCertificate(X509Certificate signCert, Optional<X509Certificate> certOpt) {
        for (TrustListWalkerAndGetter walker : walkers) {
            certOpt = walker.getAllCerts()
                    .stream().filter(e ->
                            e.getSubjectDN().getName()
                                    .equals(signCert.getIssuerDN().getName()))
                    .findFirst();
            if (certOpt.isPresent()) {
                break;
            }
        }
        return certOpt;
    }


    /**
     * Here the real signers certificate for a signedr-info is detected
     * @param certificates the certificates array
     * @param signerInfos the signerr-infos
     * @return return the real signers
     * @throws CMSException error case
     * @throws CMSSignatureException error case
     */
    private List<X509Certificate> findSigners(X509Certificate[]  certificates, SignerInfo[] signerInfos) throws CMSException, CMSSignatureException {
            List<X509Certificate> result = new ArrayList<>();
            if (signerInfos.length > 0) {
                for (SignerInfo info:signerInfos) {
                    for (X509Certificate cert: certificates) {
                        if (info.isSignerCertificate(cert)) {
                            result.add(cert);
                        }
                    }
                }
            }
            return result;

    }

    /**
     * produce a message digest object for a algorithm
     * @param contentDigestAlgorithm the algorithm
     * @return the digest object
     * @throws Exception error case
     */
    private MessageDigest makeMessageDigest(AlgorithmID contentDigestAlgorithm) throws Exception {

                    return MessageDigest.getInstance(contentDigestAlgorithm.getJcaStandardName());

    }

    /**
     * Here the message digest for the signature is created and calculated
     * @param signedData the signature content
     * @return success if the digest is correct
     */
    private boolean calculateAndCheckDigest(SignedData signedData) {
        try {
            ByteArrayOutputStream bbos = new ByteArrayOutputStream();
            InputStream inStream = signedData.getInputStream();
            MessageDigest mdTwo = makeMessageDigest(AlgorithmID.sha512);
            MessageDigest mdThree = makeMessageDigest(AlgorithmID.sha512);
            DigestOutputStream digestStream = new DigestOutputStream(bbos, mdTwo);
            copyStream(inStream, digestStream, 4096, mdThree);
            digestStream.close();
            MessageDigest streamMD = digestStream.getMessageDigest();
            bbos.close();
            inStream.close();
            byte [] first = mdThree.digest();
            byte [] second = streamMD.digest();
            boolean equal = Arrays.equals(first, second);
            if (equal) {
                System.out.println("digest equal");
            }
            return equal;
        } catch (Exception e) {
            return false;
       }
    }

    /**
     * This method copies the content and calculates the digest
     * @param in the input stream
     * @param out the output stream
     * @param bufferSize the copy buffers size
     * @param md the message digest
     * @throws IOException error case
     */
    public static void copyStream(InputStream in, OutputStream out, int bufferSize, MessageDigest md) throws IOException {

// Read bytes and write to destination until eof
        byte[] buf = new byte[bufferSize];
        int len = 0;
        while ((len = in.read(buf)) >= 0)
        {
            md.update(buf, 0, len);
            out.write(buf, 0, len);
        }
    }

    /**
     * This method checks the specified certificate chain with
     * OCSP
     * @param results the check results object
     * @param chain the certificate chain
     */
    private void checkOCSP (SignerInfoCheckResults results, X509Certificate [] chain) {
        try {
            boolean reqIsSigned = true;
            SigningUtil.KeyStoreBean bean = loadKey();
            X509Certificate[] certs = new X509Certificate[1];
            certs[0] = bean.getSelectedCert();
            int responseStatus = 0;
            URL ocspUrl = HttpOCSPClient.getOCSPUrl(chain[0]);
            OCSPResponse response;
            if (reqIsSigned == true) {
                 response = HttpOCSPClient.sendOCSPRequest(ocspUrl, bean.getSelectedKey(),
                        certs, chain, true);
            } else {
                response = HttpOCSPClient.sendOCSPRequest(ocspUrl, null,
                        null, chain, true);
            }

            responseStatus = HttpOCSPClient.getClient().parseOCSPResponse(response, true);
            String resultName = chain[0].getSubjectDN().getName();
            if (responseStatus == OCSPResponse.successful) {
                results.addOcspResult(resultName, new Tuple<String, Outcome>(response.getResponseStatusName(), Outcome.SUCCESS));
            } else if(responseStatus == OCSPResponse.tryLater) {
                results.addOcspResult(resultName, new Tuple<String, Outcome>(response.getResponseStatusName(),
                        Outcome.UNDETERMINED));
            } else {
                results.addOcspResult(resultName, new Tuple<String, Outcome>(response.getResponseStatusName(),
                        Outcome.FAILED));
            }
        } catch (Exception ex){
            throw new IllegalStateException("OCSP check failed with exception", ex);
        }
    }

    /**
     * The class holding the verification result overall
     */
    public static class VerifierResult {
        Map<String, SignerInfoCheckResults> signersCheck = new HashMap<>();
        public VerifierResult(){

        }

        public void addSignersInfo(String signersName, SignerInfoCheckResults results) {
            signersCheck.put(signersName, results);
        }


        public List<SignerInfoCheckResults> getSignersCheck() {
            List<SignerInfoCheckResults> result = new ArrayList<>();
            result.addAll(signersCheck.values());
            return result;
        }

        public Set<Map.Entry<String, SignerInfoCheckResults>> getAllResultsCheck() {
            return signersCheck.entrySet();
        }
    }

    /**
     * The class holding the check results for a specific signer-info
     */
    public static class SignerInfoCheckResults {
        Map<String, Tuple<String, Outcome>> signatureResults = new HashMap<>();
        Map<String, Tuple<String, Outcome>> ocspResults = new HashMap<>();
        SignerInfo info = null;
        Map<Tuple<String, Outcome>, List<X509Certificate>> signersChain = new HashMap<>();

        public void setInfo(SignerInfo info) {
            this.info = info;
        }

        public void addCertChain(Tuple<String,Outcome> result, List<X509Certificate> resultCerts) {
            signersChain.put(result, resultCerts);
        }

        public SignerInfo getInfo() {
            return info;
        }

        public Map<Tuple<String, Outcome>, List<X509Certificate>> getSignersChain() {
            return signersChain;
        }

        public Map<String, Tuple<String, Outcome>> getSignatureResult() {
            return signatureResults;
        }

        public Map<String, Tuple<String, Outcome>> getOcspResult() {
            return ocspResults;
        }

        public SignerInfoCheckResults addSignatureResult(String resultName, Tuple<String, Outcome> signatureResult) {
            this.signatureResults.put(resultName, signatureResult);
            return this;
        }

        public SignerInfoCheckResults addOcspResult(String resultName, Tuple<String, Outcome> ocspResult) {
            this.ocspResults.put(resultName, ocspResult);
            return this;
        }
    }

    /**
     * The cheeck result codes
     */
    public static enum Outcome {
        SUCCESS,
        FAILED,
        UNDETERMINED;
    }

}
