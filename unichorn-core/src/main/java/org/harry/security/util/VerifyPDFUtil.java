package org.harry.security.util;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import iaik.pdf.itext.PdfSignatureInstanceItext;
import iaik.pdf.signature.ApprovalSignature;
import iaik.pdf.signature.DocumentTimestamp;
import iaik.pdf.signature.PdfSignatureDetails;
import iaik.pdf.signature.PdfSignatureInstance;
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
     * Verifies all signatures in the given PDF.
     *
     * @param path
     *          path to the PDF file, that shall be verified.
     * @return true, if signatures are valid, throws an exception otherwise
     * @throws Exception
     *           if signatures are not valid or in case of errors during validation
     */
    public VerifyUtil.SignerInfoCheckResults verifyPdf(InputStream in) throws Exception {
        VerifyUtil.SignerInfoCheckResults results = new VerifyUtil.SignerInfoCheckResults();
        PdfReader reader = new PdfReader(in);
        AcroFields af = reader.getAcroFields();
        ArrayList<?> names = af.getSignatureNames();
        ArrayList<String> invalidSignatures = new ArrayList<String>();

        for (int k = 0; k < names.size(); ++k) {
            String name = (String) names.get(k);
            PdfPKCS7 pk = af.verifySignature(name);
            if (!pk.verify()) {

                invalidSignatures.add(name);
                continue;
            }

            Calendar cal = pk.getSignDate();
            Certificate[] pkc = pk.getCertificates();
            X509Certificate cert = new X509Certificate(pkc[0].getEncoded());
            String fails = CertificateVerification.verifyCertificate(cert,
                    pk.getCRLs(), cal);
            if (fails != null) {
                System.out.println("fails: " + fails);
                invalidSignatures.add(name);
                continue;
            }
            if (!pk.isRevocationValid()) {
                invalidSignatures.add(name);
            }
            algPathChecker.detectChain(cert, results);
            PdfName subfilter = pk.getFilterSubtype();
            if (subfilter.equals(PdfName.ADBE_PKCS7_DETACHED)) {
                results.addSignatureResult("subfilter type",
                        new Tuple<>("basic signature type pkcs7.detached", VerifyUtil.Outcome.SUCCESS));
            }
            //algPathChecker.checkSignatureAlgorithm();

        }

        if (invalidSignatures.size() > 0) {
            String separator = "";
            StringBuffer namesString = new StringBuffer();
            for (String signatureName : invalidSignatures) {
                namesString.append(separator);
                namesString.append(signatureName);
                separator = ", ";
            }
            if (invalidSignatures.size() > 1) {
                throw new GeneralSecurityException(
                        "the signatures " + namesString.toString() + " are invalid!");
            } else {
                throw new GeneralSecurityException(
                        "the signature " + namesString.toString() + " is invalid!");
            }
        }
        return results;

    }

    /**
     * Verify given signed PDF document.
     *
     * @param fileToBeVerified
     *          the signed or certified PDF document.
     * @throws IOException
     *           if the signed document can't be read
     * @throws PdfSignatureException
     *           if errors during verification occur
     * @throws CmsCadesException
     *           if the signature is invalid or certificates are revoked or missing
     * @throws TspVerificationException
     *           if timestamp is invalid
     * @throws CertificateException
     *           if certificate already expired
     */
    public void verifySignedPdf(InputStream fileToBeVerified)
            throws Exception {
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



}
