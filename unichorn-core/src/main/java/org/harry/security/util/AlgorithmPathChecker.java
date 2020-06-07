package org.harry.security.util;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSAlgorithmID;
import iaik.security.dsa.DSAPublicKey;
import iaik.security.ec.common.AbstractECPublicKey;
import iaik.security.rsa.RSAPublicKey;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.BasicOCSPResponse;
import iaik.x509.ocsp.OCSPResponse;
import iaik.x509.ocsp.ReqCert;
import iaik.x509.ocsp.SingleResponse;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.CertificateChainUtil;
import org.harry.security.util.ocsp.HttpOCSPClient;
import org.harry.security.util.ocsp.OCSPCRLClient;
import org.harry.security.util.trustlist.TrustListManager;


import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

import static org.harry.security.CommonConst.OCSP_URL;
import static org.harry.security.util.HttpsChecker.loadKey;

public class AlgorithmPathChecker {

    /**
     * This is the list of trust-lists provided by EU to check the path of the signers certificate
     */
    private final List<TrustListManager> walkers;

    /**
     * The signing bean
     */
    private final SigningBean bean;

    /**
     * CTOr to create this utility
     * @param walkers the trust lists
     * @param bean the signing bean
     */
    public AlgorithmPathChecker(List<TrustListManager> walkers, SigningBean bean) {
        this.walkers = walkers;
        this.bean = bean;
    }

    /**
     * Here the chain is checked for validity and consistency
     * @param signCert the signers certificate
     * @param chainIN
     * @param results the check results object
     */
    public X509Certificate[] detectChain(X509Certificate signCert, X509Certificate[] chainIN, VerifyUtil.SignerInfoCheckResults results) {
        X509Certificate[] certArray; // change to method call
        certArray = new X509Certificate[3];
        int index = 0;
        certArray = CertificateChainUtil.resolveTrustedChain(signCert, chainIN, walkers, null);
        if (certArray.length > 0) {
            results.addSignatureResult(
                    "certChain", new Tuple<>("signature chain building success", VerifyUtil.Outcome.SUCCESS));
        } else {
            results.addSignatureResult(
                    "certChain", new Tuple<>("signature chain building failed", VerifyUtil.Outcome.FAILED));
        }
        for (X509Certificate actualCert: certArray) {
            if (!CertificateWizzard.isCertificateSelfSigned(actualCert) && bean.isCheckPathOcsp()) {
                checkOCSP(actualCert, certArray, bean.isCheckOcspUseAltResponder(), results);
            }
        }
        results.addCertChain(new Tuple<>("set signer chain", VerifyUtil.Outcome.SUCCESS), Arrays.asList(certArray), certArray);
        return certArray;

    }

    /**
     * This method checks the specified certificate chain with
     * OCSP
     * @param actualCert
     * @param chain the certificate chain
     * @param altResponder
     * @param results the check results object
     */
    public void checkOCSP(X509Certificate actualCert, X509Certificate[] chain, boolean altResponder, VerifyUtil.SignerInfoCheckResults results) {
        try {
            boolean reqIsSigned = true;
            Tuple<PrivateKey, X509Certificate[]> bean = loadKey();
            X509Certificate[] certs;
            certs = bean.getSecond();
            int responseStatus = 0;
            String ocspUrl;
            if (altResponder) {
                ocspUrl = OCSP_URL;
            } else {
                ocspUrl = OCSPCRLClient.getOCSPUrl(actualCert);
            }
            OCSPResponse response = null;
            if (reqIsSigned == true && ocspUrl != null) {
                response = HttpOCSPClient.sendOCSPRequest(ocspUrl, bean.getFirst(),
                        certs, chain, ReqCert.certID, false, true);
            } else if (ocspUrl != null){
                response = HttpOCSPClient.sendOCSPRequest(ocspUrl, bean.getFirst(),
                        certs, chain, ReqCert.certID, false, true);
            }

            if (response != null) {
                responseStatus = HttpOCSPClient.getClient().parseOCSPResponse(response, true);
                String resultName = chain[0].getSubjectDN().getName();
                if (responseStatus == OCSPResponse.successful) {
                    BasicOCSPResponse basicOCSPResponse = (BasicOCSPResponse) response
                            .getResponse();
                    SingleResponse singleResponse = basicOCSPResponse.getSingleResponses()[0];
                    results.addOcspResult("ocspResult",
                            new Tuple<String, VerifyUtil.Outcome>(singleResponse.getCertStatus().toString(), VerifyUtil.Outcome.SUCCESS));
                } else if (responseStatus == OCSPResponse.tryLater) {
                    results.addOcspResult(resultName, new Tuple<String, VerifyUtil.Outcome>(response.getResponseStatusName(),
                            VerifyUtil.Outcome.INDETERMINED));
                } else {
                    results.addOcspResult(resultName, new Tuple<String, VerifyUtil.Outcome>(response.getResponseStatusName(),
                            VerifyUtil.Outcome.FAILED));
                }
            }
        } catch (Exception ex){
            throw new IllegalStateException("OCSP check failed with exception", ex);
        }
    }

    /**
     * Method to check the validity of a signature algorithm
     * @param sigAlg the signature algorithm
     * @param pubKey the public key
     * @param results the check result container
     */
    public void checkSignatureAlgorithm(AlgorithmID sigAlg, PublicKey pubKey, VerifyUtil.SignerInfoCheckResults results) {
        if (pubKey instanceof RSAPublicKey) {
            RSAPublicKey pubKeyRSA = (RSAPublicKey)pubKey;
            checkRSAKeyAlg(pubKeyRSA, results);
            checkRSAPadding(sigAlg, results);
        } else if(pubKey instanceof DSAPublicKey) {

        } else if (pubKey instanceof AbstractECPublicKey) {

        }
    }

    /**
     * TODO: for future
     * @param digestAlg the digest algorithm
     * @param results the check result container
     */
    public void checkDigestAlgorithm(AlgorithmID digestAlg, VerifyUtil.SignerInfoCheckResults results) {

    }

    public void checkRSAKeyAlg(RSAPublicKey pubKey, VerifyUtil.SignerInfoCheckResults results) {
        int lenght = pubKey.getModulus().bitLength();
        if (lenght >= 4096) {
            results.addSignatureResult("check signature algorithm", new Tuple<>("algorithm", VerifyUtil.Outcome.SUCCESS));
        } else {
            results.addSignatureResult("check signature algorithm", new Tuple<>("algorithm", VerifyUtil.Outcome.INDETERMINED));
        }
    }

    /**
     * check method for RSA Padding Version
     * @param sigAlg the signature algorithm
     * @param results the check result container
     */
    public void checkRSAPadding(AlgorithmID sigAlg, VerifyUtil.SignerInfoCheckResults results) {
        if (sigAlg.equals(CMSAlgorithmID.rsassaPss)) {
            results.addSignatureResult("check rsa padding", new Tuple<>("padding PSS 2.1", VerifyUtil.Outcome.SUCCESS));
        } else {
            results.addSignatureResult("check rsa padding", new Tuple<>("padding PSS 1.5", VerifyUtil.Outcome.INDETERMINED));
        }
    }





}
