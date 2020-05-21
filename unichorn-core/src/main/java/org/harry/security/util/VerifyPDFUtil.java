package org.harry.security.util;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.OCSPResponse;
import iaik.x509.ocsp.ReqCert;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.ocsp.HttpOCSPClient;
import org.harry.security.util.trustlist.TrustListManager;

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
    public boolean verifyPdf(String path) throws Exception {
        VerifyUtil.SignerInfoCheckResults results = new VerifyUtil.SignerInfoCheckResults();
        PdfReader reader = new PdfReader(path);
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
            algPathChecker.detectChain(cert, results);
            if (!pk.isRevocationValid()) {
                invalidSignatures.add(name);
            }
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
        return true;

    }



}
