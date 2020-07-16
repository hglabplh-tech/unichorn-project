package org.harry.security.util;

import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.PolicyInformation;
import iaik.asn1.structures.PolicyQualifierInfo;
import iaik.cms.SignerInfo;
import iaik.pdf.asn1objects.ContentTimeStamp;
import iaik.pdf.asn1objects.SignatureTimeStamp;
import iaik.pdf.cmscades.CadesSignature;
import iaik.pdf.itext.PdfSignatureInstanceItext;
import iaik.pdf.signature.ApprovalSignature;
import iaik.pdf.signature.DocumentTimestamp;
import iaik.pdf.signature.PdfSignatureDetails;
import iaik.pdf.signature.PdfSignatureInstance;
import iaik.smime.ess.SigningCertificate;
import iaik.tsp.TimeStampToken;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.trustlist.TrustListManager;

import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.List;

import static org.harry.security.util.certandkey.CSRHandler.cleanupPreparedResp;

public class VerifyPDFUtil {

    private final List<TrustListManager> walkers;
    private final SigningBean bean;
    private final AlgorithmPathChecker algPathChecker;

    /**
     * The default constructor for verification
     * @param walkers the trust lists
     */
    public VerifyPDFUtil(List<TrustListManager> walkers, SigningBean bean) {
        this.walkers = walkers;
        this.bean = bean;
        this.algPathChecker = new AlgorithmPathChecker(walkers, bean);
    }

    /**
     * Verify given signed PDF document.
     *
     * @param fileToBeVerified
     *          the signed or certified PDF document.
     *
     */
    public VerificationResults.VerifierResult verifySignedPdf(InputStream fileToBeVerified) throws Exception {
        cleanupPreparedResp();
        VerificationResults.VerifierResult result = null;
        result = new VerificationResults.VerifierResult();
        VerificationResults.SignerInfoCheckResults results = new VerificationResults.SignerInfoCheckResults();
        result.addSignersInfo("undeterminded", results);
        try {
            PdfSignatureInstance signatureInstance = new PdfSignatureInstanceItext();
            // initialize engine with path of signed pdf (to be verified)
            signatureInstance.initVerify(fileToBeVerified, null);

            System.out.println("\n#### verifying file " + fileToBeVerified + " ... ####\n");


            // use methods provided by CMSSignatureValidator class for a more detailed
            // verification
            PdfSignatureDetails[] signatures = signatureInstance.getSignatures();
            for (int i = 0; i < signatures.length; i++) {
                PdfSignatureDetails sig = signatures[i];


                // test signature details if signature is an approval signature (or a
                // certification signature)

                if (sig instanceof DocumentTimestamp) {
                    DocumentTimestamp docTS = (DocumentTimestamp) sig;
                    docTS.verifyDocumentTimestamp();
                } else if (sig instanceof ApprovalSignature) {
                    ApprovalSignature sigApp = (ApprovalSignature) sig;
                    System.out.println("signature " + (i + 1) + " of " + signatures.length
                            + " signed by: " + sigApp.getSignerCertificate().getSubjectDN().toString());
                    X509Certificate candidate = null;
                    try {
                        candidate = sigApp.verifySignatureValue();
                        System.out.println("signature valid.");
                        results.addSignatureResult("signature base check",
                                new Tuple<>("signature base check success", VerificationResults.Outcome.SUCCESS));
                    } catch (Exception ex) {
                        results.addSignatureResult("signature base check",
                                new Tuple<>("signature base check fail", VerificationResults.Outcome.FAILED));
                    }
                    // check validity of certificate at signing time
                    X509Certificate certificate = sigApp.getSignerCertificate();
                    if (candidate != null && certificate != null && certificate.equals(candidate)) {
                        results.addSignatureResult("certificate identity clear",
                                new Tuple<>("found certificates are identical", VerificationResults.Outcome.SUCCESS));
                    } else {
                        results.addSignatureResult("certificate identity uclear",
                                new Tuple<>("found certificates are not sure identical", VerificationResults.Outcome.INDETERMINED));
                    }
                    Calendar signatureDate = sigApp.getSigningTime();
                    try {
                        certificate.checkValidity(signatureDate.getTime());
                        results.addSignatureResult("certificate date range",
                                new Tuple<>("date range ok", VerificationResults.Outcome.SUCCESS));
                    } catch (Exception ex) {
                        results.addSignatureResult("certificate date range",
                                new Tuple<>("date range ok", VerificationResults.Outcome.FAILED));
                    }
                    checkSignerInfo(sigApp, results);
                    algPathChecker.detectChain(certificate, null, results);
                    System.out.println("certificate valid at signing time.");
                    if (sigApp.getSignatureTimeStampToken() != null) {
                        checkAnyTimestamp(sigApp.getSignatureTimeStampToken(), "signature timestamp", results);
                        System.out.println("timestamp signature valid.");
                    }
                }
                if (sig.isModified()) {
                    System.out.println("signature " + sig.getName() + " has been modified.");
                }
            }
        } catch (Exception ex) {
            results.addSignatureResult("unrecoverable error",
                    new Tuple<>(ex.getMessage(), VerificationResults.Outcome.FAILED));
        }
        return result;
    }

    /**
     * check the signer info values of a given Approval Signature.
     * Here also a ByteRange check is done
     * @param sigApp the approval signature
     * @param results the results container
     * @throws Exception error case
     */
    public void checkSignerInfo(ApprovalSignature sigApp, VerificationResults.SignerInfoCheckResults results) throws Exception {
        CadesSignature signature = sigApp.getCMSSignature();
        SignerInfo[] infos = signature.getSignerInfos();
        int[] range = sigApp.getByteRange();
        boolean success = checkByteRange(range);
        if (success) {
            results.addSignatureResult("byte range check", new Tuple<>("basic check ok", VerificationResults.Outcome.SUCCESS));
        } else {
            results.addSignatureResult("byte range check", new Tuple<>("basic check ok", VerificationResults.Outcome.FAILED));
        }
        sigApp.isWholeDocumentCoveredByByteRange();
        X509Certificate signer = sigApp.getSignerCertificate();
        for (SignerInfo info:infos) {
            SigningCertificate certificate = info.getSigningCertificateAttribute();
            if (certificate  != null) {
                PolicyInformation[] policyInformations = certificate.getPolicies();
                for (PolicyInformation policyInfo : policyInformations) {
                    PolicyQualifierInfo[] qualifiers = policyInfo.getPolicyQualifiers();
                    for (PolicyQualifierInfo qualifierInfo : qualifiers) {
                        results.addSignatureResult("qualifierInfo",
                                new Tuple<>(qualifierInfo.toString(), VerificationResults.Outcome.SUCCESS));
                    }
                }
            }
            AlgorithmID signatureAlg = info.getSignatureAlgorithm();
            results.addSignatureResult("signatureAlgorithmInfo",
                    new Tuple<>(signatureAlg.getImplementationName(), VerificationResults.Outcome.SUCCESS));
            algPathChecker.checkSignatureAlgorithm(signatureAlg, signer.getPublicKey(), results);
            AlgorithmID digestAlg = info.getDigestAlgorithm();
            results.addSignatureResult("digestAlgorithmInfo",
                    new Tuple<>(digestAlg.getImplementationName(), VerificationResults.Outcome.SUCCESS));

        }

        for (int index = 0; index< infos.length; index++) {
            ContentTimeStamp[] cTimeStamps = signature.getContentTimeStamps(index);
            SignatureTimeStamp[] sTimeStamps = signature.getSignatureTimeStamps(index);
            for (ContentTimeStamp tsp: cTimeStamps) {
                checkAnyTimestamp(tsp.getTimeStampToken(), "content timestamp", results);
            }
            for (SignatureTimeStamp tsp:sTimeStamps) {
                checkAnyTimestamp(tsp.getTimeStampToken(), "signature timestamp", results);
            }
        }

    }

    private boolean checkByteRange(int[] byteRange) {
        boolean success = true;

        final int zeroIndex = byteRange[0];
        final int contentLengthBeforeSig = byteRange[1];
        final int contentLengthIncludingSig = byteRange[2];
        final int contentLengthAfterSig = byteRange[3];
        if (zeroIndex != 0) {
            success = false;
        }
        if (contentLengthBeforeSig <=0 ) {
            success = false;
        }
        if (contentLengthIncludingSig <= contentLengthBeforeSig) {
            success = false;
        }
        if (contentLengthAfterSig <= 0)  {
            success = false;
        }

        return success;
    }

    /**
     * Here the timestamps for content signature and archive are checked as well as their signers certificates
     * @param token the time-stamp-token
     * @param tokenType the token type for string output
     * @param results the check result container
     * @throws CertificateException error case
     * @throws NoSuchAlgorithmException error case
     */
    public void checkAnyTimestamp(TimeStampToken token, String tokenType, VerificationResults.SignerInfoCheckResults results) throws CertificateException, NoSuchAlgorithmException {
        if (token != null) {
            try {
                token.verifyTimeStampToken();
            } catch(Exception ex) {
                return;
            }

            SignerInfo info = token.getSignerInfo();
            AlgorithmID signatureAlg = info.getSignatureAlgorithm();
            results.addSignatureResult("timestamp signatureAlgorithmInfo " + tokenType,
                    new Tuple<>(signatureAlg.getImplementationName(), VerificationResults.Outcome.SUCCESS));
            AlgorithmID digestAlg = info.getDigestAlgorithm();
            results.addSignatureResult("timestamp digestAlgorithmInfo " + tokenType,
                    new Tuple<>(digestAlg.getImplementationName(), VerificationResults.Outcome.SUCCESS));
            X509Certificate signingCert = Util.convertCertificate(token.getSigningCertificate());
            System.out.println(signingCert.toString(true));
            X509Certificate[] certs = Util.convertCertificateChain(token.getCertificates());
            X509Certificate[] result = Util.arrangeCertificateChain(certs, false);
            boolean ocspCheck = bean.isCheckPathOcsp();
            bean.setCheckPathOcsp(false);
            AlgorithmPathChecker checker  = new AlgorithmPathChecker(walkers, bean);
            checker.detectChain(signingCert, result, results);
            bean.setCheckPathOcsp(ocspCheck);
        }
    }



}
