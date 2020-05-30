package org.harry.security.util;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.PolicyInformation;
import iaik.asn1.structures.PolicyQualifierInfo;
import iaik.cms.SignerInfo;
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
import iaik.x509.ocsp.OCSPResponse;
import iaik.x509.ocsp.ReqCert;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.ocsp.HttpOCSPClient;
import org.harry.security.util.trustlist.TrustListManager;

import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Optional;

import static org.harry.security.util.HttpsChecker.loadKey;
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
    public VerifyUtil.VerifierResult verifySignedPdf(InputStream fileToBeVerified) throws Exception {
        cleanupPreparedResp();
        VerifyUtil.VerifierResult result = null;
        result = new VerifyUtil.VerifierResult();
        VerifyUtil.SignerInfoCheckResults results = new VerifyUtil.SignerInfoCheckResults();
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
                                new Tuple<>("signature base check success", VerifyUtil.Outcome.SUCCESS));
                    } catch (Exception ex) {
                        results.addSignatureResult("signature base check",
                                new Tuple<>("signature base check fail", VerifyUtil.Outcome.FAILED));
                    }
                    // check validity of certificate at signing time
                    X509Certificate certificate = sigApp.getSignerCertificate();
                    if (candidate != null && certificate != null && certificate.equals(candidate)) {
                        results.addSignatureResult("certificate identity clear",
                                new Tuple<>("found certificates are identical", VerifyUtil.Outcome.SUCCESS));
                    } else {
                        results.addSignatureResult("certificate identity uclear",
                                new Tuple<>("found certificates are not sure identical", VerifyUtil.Outcome.UNDETERMINED));
                    }
                    Calendar signatureDate = sigApp.getSigningTime();
                    try {
                        certificate.checkValidity(signatureDate.getTime());
                        results.addSignatureResult("certificate date range",
                                new Tuple<>("date range ok", VerifyUtil.Outcome.SUCCESS));
                    } catch (Exception ex) {
                        results.addSignatureResult("certificate date range",
                                new Tuple<>("date range ok", VerifyUtil.Outcome.FAILED));
                    }
                    checkSignerInfo(sigApp, results);
                    algPathChecker.detectChain(certificate, results);
                    System.out.println("certificate valid at signing time.");
                    if (sigApp.getSignatureTimeStampToken() != null) {
                        sigApp.verifySignatureTimestampImprint();
                        System.out.println("timestamp signature valid.");
                    }
                }
                if (sig.isModified()) {
                    System.out.println("signature " + sig.getName() + " has been modified.");
                }
            }
        } catch (Exception ex) {
            results.addSignatureResult("unrecoverable error",
                    new Tuple<>(ex.getMessage(), VerifyUtil.Outcome.FAILED));
        }
        return result;
    }

    public void checkSignerInfo(ApprovalSignature sigApp, VerifyUtil.SignerInfoCheckResults results) throws Exception {
        CadesSignature signature = sigApp.getCMSSignature();
        SignerInfo[] infos = signature.getSignerInfos();
        int[] range = sigApp.getByteRange();
        boolean success = checkByteRange(range);
        if (success) {
            results.addSignatureResult("byte range check", new Tuple<>("basic check ok", VerifyUtil.Outcome.SUCCESS));
        } else {
            results.addSignatureResult("byte range check", new Tuple<>("basic check ok", VerifyUtil.Outcome.FAILED));
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
                                new Tuple<>(qualifierInfo.toString(), VerifyUtil.Outcome.SUCCESS));
                    }
                }
            }
            AlgorithmID signatureAlg = info.getSignatureAlgorithm();
            results.addSignatureResult("signatureAlgorithmInfo",
                    new Tuple<>(signatureAlg.getImplementationName(), VerifyUtil.Outcome.SUCCESS));
            algPathChecker.checkSignatureAlgorithm(signatureAlg, signer.getPublicKey(), results);
            AlgorithmID digestAlg = info.getDigestAlgorithm();
            results.addSignatureResult("digestAlgorithmInfo",
                    new Tuple<>(digestAlg.getImplementationName(), VerifyUtil.Outcome.SUCCESS));

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

    public void checkAnyTimestamp(TimeStampToken token, String tokenType, VerifyUtil.SignerInfoCheckResults results) throws CertificateException, NoSuchAlgorithmException {
        if (token != null) {
            try {
                token.verifyTimeStampToken();
            } catch(Exception ex) {
                return;
            }
            SignerInfo info = token.getSignerInfo();
            AlgorithmID signatureAlg = info.getSignatureAlgorithm();
            results.addSignatureResult("timestamp signatureAlgorithmInfo",
                    new Tuple<>(signatureAlg.getImplementationName(), VerifyUtil.Outcome.SUCCESS));
            AlgorithmID digestAlg = info.getDigestAlgorithm();
            results.addSignatureResult("timestamp digestAlgorithmInfo",
                    new Tuple<>(digestAlg.getImplementationName(), VerifyUtil.Outcome.SUCCESS));
            java.security.cert.X509Certificate signingCert = token.getSigningCertificate();
            X509Certificate iaikVersion = Util.convertCertificate(signingCert);
            algPathChecker.detectChain(iaikVersion, results);
        }
    }


}
