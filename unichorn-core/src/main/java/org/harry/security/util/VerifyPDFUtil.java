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
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.OCSPResponse;
import iaik.x509.ocsp.ReqCert;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.ocsp.HttpOCSPClient;
import org.harry.security.util.trustlist.TrustListManager;

import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Optional;

import static org.harry.security.util.HttpsChecker.loadKey;

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
     * @throws Exception
     *           if the signed document can't be read

     */
    public void verifySignedPdf(InputStream fileToBeVerified)
            throws Exception {
        VerifyUtil.SignerInfoCheckResults results = new VerifyUtil.SignerInfoCheckResults();
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
                DocumentTimestamp docTS = (DocumentTimestamp)sig;
                docTS.verifyDocumentTimestamp();
            } else if (sig instanceof ApprovalSignature) {
                ApprovalSignature sigApp = (ApprovalSignature) sig;
                System.out.println("signature " + (i + 1) + " of " + signatures.length
                        + " signed by: " + sigApp.getSignerCertificate().getSubjectDN().toString());
                sigApp.verifySignatureValue();
                System.out.println("signature valid.");

                // check validity of certificate at signing time
                X509Certificate certificate = sigApp.getSignerCertificate();
                Calendar signatureDate = sigApp.getSigningTime();
                certificate.checkValidity(signatureDate.getTime());
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
    }

    public void checkSignerInfo(ApprovalSignature sigApp, VerifyUtil.SignerInfoCheckResults results) throws Exception {
        CadesSignature signature = sigApp.getCMSSignature();
        SignerInfo[] infos = signature.getSignerInfos();
        sigApp.isWholeDocumentCoveredByByteRange();
        X509Certificate signer = sigApp.getSignerCertificate();
        for (SignerInfo info:infos) {
            SigningCertificate certificate = info.getSigningCertificateAttribute();
            PolicyInformation[] policyInformations = certificate.getPolicies();
            for (PolicyInformation policyInfo: policyInformations) {
                PolicyQualifierInfo[] qualifiers = policyInfo.getPolicyQualifiers();
                for (PolicyQualifierInfo qualifierInfo: qualifiers) {
                    results.addSignatureResult("qualifierInfo",
                            new Tuple<>(qualifierInfo.toString(), VerifyUtil.Outcome.SUCCESS));
                }
            }
            AlgorithmID signatureAlg = info.getSignatureAlgorithm();
            algPathChecker.checkSignatureAlgorithm(signatureAlg, signer.getPublicKey(), results);
            AlgorithmID digestAlg = info.getDigestAlgorithm();

        }

    }




}
