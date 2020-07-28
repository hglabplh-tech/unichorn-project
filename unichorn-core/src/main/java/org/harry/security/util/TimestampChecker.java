package org.harry.security.util;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.SignerInfo;
import iaik.tsp.TimeStampToken;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.trustlist.TrustListManager;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;

public class TimestampChecker {

    private final List<TrustListManager> walkers;
    private final SigningBean bean;
    private final AlgorithmPathChecker algPathChecker;

    /**
     * The default constructor for verification
     * @param walkers the trust lists
     */
    public TimestampChecker(List<TrustListManager> walkers, SigningBean bean) {
        this.walkers = walkers;
        this.bean = bean;
        this.algPathChecker = new AlgorithmPathChecker(walkers, bean);
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
        VerificationResults.TimestampResult tstResult = new VerificationResults.TimestampResult();
        if (token != null) {
            try {
                token.verifyTimeStampToken();
                tstResult.addFormatResult("formatOK",
                        new Tuple<>("The format is ok", VerificationResults.Outcome.SUCCESS));
                tstResult.addSignatureResult("sigMathOk",
                        new Tuple<>("The sig math is ok", VerificationResults.Outcome.SUCCESS));
            } catch(Exception ex) {
                tstResult.addFormatResult("formatOK",
                        new Tuple<>("The format is NOT ok", VerificationResults.Outcome.FAILED));
                tstResult.addSignatureResult("sigMathOk",
                        new Tuple<>("The sig math is NOT ok", VerificationResults.Outcome.FAILED));
                return;
            }

            SignerInfo info = token.getSignerInfo();
            results.addTimestampResult(tokenType, tstResult);
            AlgorithmID signatureAlg = info.getSignatureAlgorithm();
            results.addSignatureResult("timestamp signatureAlgorithmInfo " + tokenType,
                    new Tuple<>(signatureAlg.getImplementationName(), VerificationResults.Outcome.SUCCESS));
            tstResult.addSignatureResult("signatureAlgorithmInfo",
                    new Tuple<>(signatureAlg.getImplementationName(), VerificationResults.Outcome.SUCCESS));
            AlgorithmID digestAlg = info.getDigestAlgorithm();
            results.addSignatureResult("timestamp digestAlgorithmInfo " + tokenType,
                    new Tuple<>(digestAlg.getImplementationName(), VerificationResults.Outcome.SUCCESS));
            tstResult.addSignatureResult("digestAlgorithmInfo",
                    new Tuple<>(digestAlg.getImplementationName(), VerificationResults.Outcome.SUCCESS));
            X509Certificate signingCert = Util.convertCertificate(token.getSigningCertificate());
            System.out.println(signingCert.toString(true));
            X509Certificate[] certs = Util.convertCertificateChain(token.getCertificates());
            X509Certificate[] result = Util.arrangeCertificateChain(certs, false);
            boolean ocspCheck = bean.isCheckPathOcsp();
            bean.setCheckPathOcsp(false);
            AlgorithmPathChecker checker  = new AlgorithmPathChecker(walkers, bean);
            X509Certificate[] chain = checker.detectChain(signingCert, result, results);
            if (chain != null && chain.length > 1) {
                tstResult.addCertChain(chain);
            } else {
                tstResult.addCertChain(null);
            }
            bean.setCheckPathOcsp(ocspCheck);
        }
    }

}
