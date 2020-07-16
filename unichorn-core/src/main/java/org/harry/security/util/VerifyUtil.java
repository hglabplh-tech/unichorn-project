package org.harry.security.util;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.AttributeValue;
import iaik.asn1.structures.Name;
import iaik.cms.*;
import iaik.cms.attributes.CounterSignature;
import iaik.pdf.asn1objects.*;
import iaik.pdf.cmscades.CadesSignatureStream;
import iaik.pdf.cmscades.CmsCadesException;
import iaik.smime.attributes.SignatureTimeStampToken;
import iaik.tsp.TimeStampToken;
import iaik.tsp.TspVerificationException;
import iaik.utils.Util;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.attr.AttributeCertificate;
import iaik.x509.ocsp.*;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.trustlist.TrustListManager;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;

/**
 * This class is designed to verify CMS signatures checking their mathematical and other validity
 * @author Harald Glab-Plhak
 */
public class VerifyUtil {

    /**
     * This is the list of trust-lists provided by EU to check the path of the signers certificate
     */
    private final List<TrustListManager> walkers;

    private final SigningBean bean;

    private final AlgorithmPathChecker algPathChecker;


    /**
     * The default constructor for verification
     * @param walkers the trust lists
     */
    public VerifyUtil(List<TrustListManager> walkers, SigningBean bean) {
        this.walkers = walkers;
        this.bean = bean;
        this.algPathChecker = new AlgorithmPathChecker(walkers, bean);
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
    public VerificationResults.VerifierResult verifyCMSSignature(InputStream signature, InputStream data) {
        VerificationResults.VerifierResult result = null;
        try {
            ContentInfoStream cis = new ContentInfoStream(signature);

            SignedDataStream signedData = new SignedDataStream(cis.getContentInputStream());
            if (signedData.getMode() == SignedData.EXPLICIT) {
                if (data == null) {
                    throw new IllegalStateException("data stream is null though signature is explicit");
                }
                signedData.setInputStream(data);
            }

            //cadesSig.verifySignatureValue(0);
            SigningUtil.eatStream(signedData.getInputStream());
            SignerInfo [] signerInfos;
            signerInfos = signedData.getSignerInfos();
            List<X509Certificate> signCertList =
            findSigners(signedData.getX509Certificates(), signerInfos);
            result = isSuccessOfSigner(signedData, signerInfos, signCertList);
            CertificateSet certificateSet = signedData.getCertificateSet();
            checkAttributeCertIfThere(certificateSet, result.getSignersCheck().get(0));
            int index = 0;
            for (X509Certificate out: signCertList) {
                FileOutputStream stream = new FileOutputStream("./certificate(" + index +").pem");
                CertWriterReader writer = new CertWriterReader(out);
                writer.writeToFilePEM(stream);
                index++;
            }
            /*SignatureTimeStamp[]
            tsp = cadesSig.getSignatureTimeStamps(signCertList.get(0));
            signatureTimestampCheck(tsp);

            ContentTimeStamp[] tspContent = cadesSig.getContentTimeStamps(signCertList.get(0));
            contentTimestampCheck(tspContent); */
        } catch (Exception ex) {
            throw new IllegalStateException("cannot verify signature reason is", ex);
        }
        return result;
    }

    /**
     * Shows some possible verification steps, i.e. verifies the signature value and the timestamp if
     * included.
     *
     * @param signature
     *          encoded cades signature
     * @param data
     *          data, that has been signed with the given signature

     */
    public VerificationResults.VerifierResult verifyCadesSignature(InputStream signature, InputStream data) {
        VerificationResults.VerifierResult vResult = new VerificationResults.VerifierResult();
        VerificationResults.SignerInfoCheckResults results = new VerificationResults.SignerInfoCheckResults();
                try {
                    CadesSignatureStream cadesSig = new CadesSignatureStream(signature, data);
                    int signerInfoLength = cadesSig.getSignerInfos().length;

                    System.out.println("Signature contains " + signerInfoLength + " signer infos");


                    SignedDataStream signedData = cadesSig.getSignedDataObject();
                    CertificateSet certificateSet = signedData.getCertificateSet();
                    results.addFormatResult("sigFormatOk", new Tuple<>("the signature is well formed", VerificationResults.Outcome.SUCCESS));

                    int j = 0;
                    for (SignerInfo info: cadesSig.getSignerInfos()) {
                        AlgorithmID sigAlg = info.getSignatureAlgorithm();
                        AlgorithmID digestAlg = info.getDigestAlgorithm();

                        results.addSignatureResult("sigAlg",
                                new Tuple<>(sigAlg.getImplementationName(), VerificationResults.Outcome.SUCCESS));
                        results.addSignatureResult("digestAlg",
                                new Tuple<>(digestAlg.getImplementationName(), VerificationResults.Outcome.SUCCESS));
                        X509Certificate signCert = cadesSig.verifySignatureValue(j);
                        if(signCert != null) {
                            results.addSignatureResult("sigMathOk",
                                    new Tuple<>("signature is math correct", VerificationResults.Outcome.SUCCESS));
                        } else {
                            results.addSignatureResult("sigMathOk",
                                    new Tuple<>("signature is math incorrect", VerificationResults.Outcome.FAILED));
                        }
                        if (bean.isCheckForQualified()) {
                            CertChecker.checkQualified(signCert, results);
                        }
                        checkAttributeCertIfThere(certificateSet, results);
                        vResult.addSignersInfo(signCert.getSubjectDN().getName(), results);
                        results.addSignatureResult("signature value",
                                new Tuple<>(signCert.getSubjectDN().getName(), VerificationResults.Outcome.SUCCESS));
                        System.out.println("Signer " + (j + 1) + " signature value is valid.");
                        vResult.addSignersInfo(signCert.getSubjectDN().getName(), results);
                        checkCounterSignatures(info, signCert, results);
                        algPathChecker.checkSignatureAlgorithm(sigAlg, signCert.getPublicKey(), results);
                        algPathChecker.detectChain(signCert, null, results);
                        // tsp verification
                        SignatureTimeStamp[] timestamps = cadesSig.getSignatureTimeStamps(j);
                        for (SignatureTimeStamp tst : timestamps) {
                            System.out.println("Signer info " + (j + 1) + " contains a signature timestamp.");
                            tst.verifyTimeStampToken(null);
                            results.addSignatureResult("timestamp check",
                                    new Tuple<>(signCert.getSubjectDN().getName(), VerificationResults.Outcome.SUCCESS));
                        }

                        ArchiveTimeStampv3[] archiveTimeStamps = cadesSig.getArchiveTimeStamps(signCert);
                        for (ArchiveTimeStampv3 tst : archiveTimeStamps) {
                            System.out.println("Signer info " + (j + 1) + " contains a archive timestamp.");
                            tst.verifyTimeStampToken(null);

                            results.addSignatureResult("timestamp check",
                                    new Tuple<>(signCert.getSubjectDN().getName(), VerificationResults.Outcome.SUCCESS));
                        }
                        j++;
                        cadesExtractTimestampAndData(results, cadesSig);
                    }
                } catch (Exception ex) {
                    results.addFormatResult("sigFormatOk",
                            new Tuple<>("the signature is NOT well formed", VerificationResults.Outcome.FAILED));
                    throw new IllegalStateException("failure", ex);
                }

                return vResult;
    }

    /**
     * Check the existence and validity of a attribute certificate this is optional
     * @param certificateSet the certificate set in which we search
     * @param results the check results container
     * @throws CertificateException error case
     * @throws NoSuchAlgorithmException error case
     * @throws InvalidKeyException error case
     * @throws NoSuchProviderException error case
     * @throws SignatureException error case
     */
    private void checkAttributeCertIfThere(CertificateSet certificateSet, VerificationResults.SignerInfoCheckResults results) throws
            CertificateException, NoSuchAlgorithmException, InvalidKeyException,
            NoSuchProviderException, SignatureException {
        X509Certificate [] certificates = certificateSet.getX509Certificates();
        X509Certificate[] arranged = Util.arrangeCertificateChain(certificates, false);
        for (Certificate candidate: certificateSet.getAttributeCertificates()) {
            AttributeCertificate attrCert = new AttributeCertificate(candidate.getEncoded());
            try {
                attrCert.verify(arranged[0].getPublicKey());
                results.addSignatureResult("attribute certificate check", new Tuple<>("attrCertCheck", VerificationResults.Outcome.SUCCESS));
            } catch(Exception ex) {
                results.addSignatureResult("attribute certificate check", new Tuple<>("attrCertCheck", VerificationResults.Outcome.FAILED));
            }

        }
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
    public VerificationResults.VerifierResult isSuccessOfSigner(
                                     SignedDataStream signedData,
                                     SignerInfo[] signerInfos,
                                     List<X509Certificate> signCertList) throws CMSSignatureException {
        try {
            VerificationResults.VerifierResult vResult = new VerificationResults.VerifierResult();
            if (signCertList.size() > 0) {
                for (SignerInfo info : signerInfos) {
                    AlgorithmID sigAlg = info.getSignatureAlgorithm();
                    AlgorithmID digestAlg = info.getDigestAlgorithm();
                    VerificationResults.SignerInfoCheckResults results = new VerificationResults.SignerInfoCheckResults();
                    results.setInfo(info);
                    results.addFormatResult("sigFormatOk",
                            new Tuple<>("the signature is well formed", VerificationResults.Outcome.SUCCESS));
                    results.addSignatureResult("signature algorithm",
                            new Tuple<>(sigAlg.getImplementationName(), VerificationResults.Outcome.SUCCESS));
                    results.addSignatureResult("digest algorithm",
                            new Tuple<>(digestAlg.getImplementationName(), VerificationResults.Outcome.SUCCESS));
                    for (X509Certificate signCert : signCertList) {
                        algPathChecker.checkSignatureAlgorithm(sigAlg, signCert.getPublicKey(), results);
                        if (info.isSignerCertificate(signCert)) {
                            if (bean.isCheckForQualified()) {
                                CertChecker.checkQualified(signCert, results);
                            }
                            vResult.addSignersInfo(signCert.getSubjectDN().getName(), results);
                            try {
                                checkCounterSignatures(info, signCert, results);
                                if (info.verifySignature(signCert.getPublicKey())) {
                                    results.addSignatureResult("sigMathOk",
                                            new Tuple<>("signature is math correct", VerificationResults.Outcome.SUCCESS));
                                    results.addSignatureResult(signCert.getSubjectDN().getName(),
                                            new Tuple<>("signature base check succeded", VerificationResults.Outcome.SUCCESS));

                                    algPathChecker.detectChain(signCert, null, results);

                                } else {
                                    results.addSignatureResult("sigMathOk",
                                            new Tuple<>("signature is math incorrect", VerificationResults.Outcome.FAILED));
                                    results.addSignatureResult(signCert.getSubjectDN().getName(),
                                            new Tuple<>("signature check failed", VerificationResults.Outcome.FAILED));
                                }
                            } catch (Exception ex) {
                                results.addSignatureResult(signCert.getSubjectDN().getName(),
                                        new Tuple<>(ex.getMessage(), VerificationResults.Outcome.FAILED));
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
     * Verifies the archive timestamp, extracts the archived verification data and uses this data to
     * verify the signature.
     *
     * @param results
     *          the check results container
     * @param cadesSig
     *          the cades-signature object
     * @throws Exception
     *           if the signature can't be read or verified
     */
    public void cadesExtractTimestampAndData(VerificationResults.SignerInfoCheckResults results,
                                             CadesSignatureStream cadesSig)
            throws Exception {
        SignedDataStream signedData = cadesSig.getSignedDataObject();
        SignerInfo[] signerInfos = signedData.getSignerInfos();
        for (int i = 0; i < signerInfos.length; i++) {
            X509Certificate signerCert = cadesSig.verifySignatureValue(i);
            results.addSignatureResult("certificate found", new Tuple<String, VerificationResults.Outcome>(signerCert.getSubjectDN().getName(),
                    VerificationResults.Outcome.SUCCESS));
            ArchiveTimeStampv3[] archiveTsps = cadesSig.getArchiveTimeStamps(signerCert);
            for (ArchiveTimeStampv3 tsp : archiveTsps) {
                tsp.verifyTimeStampToken(null);
                results.addSignatureResult("archive timestamp verified", new Tuple<String, VerificationResults.Outcome>(tsp.getName(),
                        VerificationResults.Outcome.SUCCESS));
                System.out.println("Archive time-stamp signature verified successfully.");
                AbstractAtsHashIndex dataReferences = tsp.getAtsHashIndex();
                // ETSI EN 319 122-1 defines the ats-hash-index attribute to be invalid if it includes
                // references that do not match objects in the archived signature
                if (dataReferences instanceof AtsHashIndexv3)
                    if (dataReferences.containsReferencesWithoutOriginalValues(cadesSig,
                            signerInfos[i])) {
                        results.addSignatureResult("check archive references", new Tuple<String, VerificationResults.Outcome>(tsp.getName(),
                                VerificationResults.Outcome.FAILED));
                        System.out.println(
                                "!! Archive time-stamp invalid: ATSHashIndexv3 contains references without matching data !!");
                    } else {
                        results.addSignatureResult("check archive references", new Tuple<String, VerificationResults.Outcome>(tsp.getName(),
                                VerificationResults.Outcome.SUCCESS));
                    }

                // retrieved the archived data that can be used for verification

                Certificate[] certs = dataReferences.getIndexedCertificates(cadesSig);
                BasicOCSPResponse [] ocspResponses = dataReferences
                        .getIndexedOcspResponses(cadesSig);
                HashMap<ReqCert, BasicOCSPResponse> ocspResponsesMap = new HashMap<ReqCert, BasicOCSPResponse>();
                for (BasicOCSPResponse resp : ocspResponses) {
                    SingleResponse[] singleResponses = resp.getSingleResponses();
                    for (SingleResponse singleResp : singleResponses) {
                        ocspResponsesMap.put(singleResp.getReqCert(), resp);
                    }
                }
                X509CRL[] crls = dataReferences.getIndexedCrls(cadesSig);

                // verify archived signature - only exemplary verification

                X509Certificate[] signerCertChain = algPathChecker.detectChain(signerCert, null, results);

                if (signerCertChain.length > 1) {
                    CertID certID = new CertID(AlgorithmID.sha1,
                            (Name) signerCertChain[1].getSubjectDN(), signerCertChain[1].getPublicKey(),
                            signerCert.getSerialNumber());
                    ReqCert reqCert = new ReqCert(ReqCert.certID, certID);
                    BasicOCSPResponse resp = ocspResponsesMap.get(reqCert);
                    if (resp != null) {
                        resp.verify(signerCertChain[1].getPublicKey());
                        CertStatus stat = resp.getSingleResponse(reqCert).getCertStatus();
                        if (stat.getCertStatus() != CertStatus.GOOD) {
                            results.addSignatureResult("included ocsp verified", new Tuple<String, VerificationResults.Outcome>(tsp.getName(),
                                    VerificationResults.Outcome.FAILED));
                        } else {
                            results.addSignatureResult("included ocsp verified", new Tuple<String, VerificationResults.Outcome>(tsp.getName(),
                                    VerificationResults.Outcome.SUCCESS));
                        }
                        System.out
                                .println("Signer certificate status 'good' in archived OCSP response.");
                    }
                }

                if (crls.length > 0) {
                    for (X509CRL crl : crls) {
                        if (crl.containsCertificate(signerCert) != null)
                            throw new CmsCadesException("Signer certificate of signer info " + i
                                    + " on crl and therefore revoked.");
                    }
                    System.out
                            .println("Signer certificate not found on an archived revocation list.");
                }

                // handle archived unsigned attributes, e.g. check signature timestamps
                ArrayList<SignatureTimeStamp> sigTsps = new ArrayList<SignatureTimeStamp>();
                if (dataReferences instanceof AtsHashIndex) {
                    Attribute[] attributes = ((AtsHashIndex) dataReferences)
                            .getIndexedUnsignedAttributes(signerInfos[i]);
                    for (Attribute attr : attributes) {
                        if (attr.getType().equals(SignatureTimeStamp.oid)) {
                            SignatureTimeStampToken stsp = (SignatureTimeStampToken) attr
                                    .getAttributeValue();
                            sigTsps
                                    .add(new SignatureTimeStamp(stsp, signerInfos[i].getSignatureValue()));
                        }
                    }
                } else if (dataReferences instanceof AtsHashIndexv3) {
                    AttributeValue[] attributeValues = ((AtsHashIndexv3) dataReferences)
                            .getIndexedUnsignedAttrValues(signerInfos[i]);
                    for (AttributeValue attr : attributeValues) {
                        if (attr.getAttributeType().equals(SignatureTimeStamp.oid)) {
                            sigTsps.add(
                                    new SignatureTimeStamp(new SignatureTimeStampToken(attr.toASN1Object()),
                                            signerInfos[i].getSignatureValue()));
                        }
                    }
                }
                for (SignatureTimeStamp sigTsp : sigTsps) {
                    sigTsp.verifyTimeStampToken(null);
                    System.out.println("Archived signature timestamp valid. Signature time: "
                            + sigTsp.getTimeStampToken().getTSTInfo().getGenTime());
                }
            }
        }
    }

    public void checkCounterSignatures(SignerInfo signerInfo, X509Certificate signingCert, VerificationResults.SignerInfoCheckResults results) {
        Attribute counterAttr = signerInfo.getUnsignedAttribute(ObjectID.countersignature);
        if (counterAttr != null ) {

            try {
                AttributeValue[] values = counterAttr.getAttributeValues();
                for (AttributeValue value : values) {
                    CounterSignature signature = (CounterSignature) value;
                    Attribute attrTry = signature.getUnsignedAttribute(ObjectID.signingCertificate);
                    Attribute attr = signature.getSignedAttribute(ObjectID.signingCertificate);
                    if (signature.verify(this.bean.getCounterKeyStoreBean()
                            .getSelectedCert()
                            .getPublicKey(),
                            signerInfo)) {
                        results.addSignatureResult("counter_sig", new Tuple<String, VerificationResults.Outcome>("counter signature verified ok",
                                VerificationResults.Outcome.SUCCESS));
                        algPathChecker.checkSignatureAlgorithm(signature.getSignatureAlgorithm(),
                                this.bean.getCounterKeyStoreBean()
                                        .getSelectedCert()
                                        .getPublicKey(),
                                results);
                    } else {
                        results.addSignatureResult("counter_sig", new Tuple<String, VerificationResults.Outcome>("counter signature verified NOT ok",
                                VerificationResults.Outcome.FAILED));
                    }

                }
            } catch (Exception ex) {
                // set results
                throw new IllegalStateException("verifying counter signatures failed");
            }
        }

    }

}
