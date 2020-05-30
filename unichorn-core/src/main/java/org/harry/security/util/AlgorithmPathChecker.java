package org.harry.security.util;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.asn1.structures.RDN;
import iaik.cms.CMSAlgorithmID;
import iaik.security.dsa.DSA;
import iaik.security.dsa.DSAPublicKey;
import iaik.security.ec.common.AbstractECPublicKey;
import iaik.security.rsa.RSAPssPublicKey;
import iaik.security.rsa.RSAPublicKey;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.OCSPResponse;
import iaik.x509.ocsp.ReqCert;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.ocsp.HttpOCSPClient;
import org.harry.security.util.trustlist.TrustListManager;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.harry.security.util.HttpsChecker.loadKey;

public class AlgorithmPathChecker {

    /**
     * This is the list of trust-lists provided by EU to check the path of the signers certificate
     */
    private final List<TrustListManager> walkers;

    private final SigningBean bean;

    public AlgorithmPathChecker(List<TrustListManager> walkers, SigningBean bean) {
        this.walkers = walkers;
        this.bean = bean;
    }

    /**
     * Here the chain is checked for validity and consistency
     * @param signCert the signers certificate
     * @param results the check results object
     */
    public X509Certificate[] detectChain(X509Certificate signCert, VerifyUtil.SignerInfoCheckResults results) {
        X509Certificate[] certArray;
        certArray = new X509Certificate[3];
        X509Certificate actualCert = signCert;
        int index = 0;
        while (!CertificateWizzard.isCertificateSelfSigned(actualCert)) {
            results.addSignatureResult(
                    actualCert.getSubjectDN().getName(), new Tuple<>("signature ok", VerifyUtil.Outcome.SUCCESS));
            Optional<X509Certificate> certOpt = Optional.empty();
            certOpt = getX509IssuerCertificate(actualCert, certOpt);
            if (certOpt.isPresent()) {
                System.out.println("found subject:" + certOpt.get().getSubjectDN().getName());
                certArray[index] = actualCert;
                certArray[index + 1] = certOpt.get();
                if (bean.isCheckPathOcsp()) {
                    checkOCSP(results, certArray);
                }
            } else {
                results.addSignatureResult(
                        "", new Tuple<>("signature chain building failed", VerifyUtil.Outcome.FAILED));
            }
            if (certOpt.isPresent()) {
                actualCert = certOpt.get();
            } else {
                break;
            }
            index++;
        }
        results.addCertChain(new Tuple<>("set signer chain", VerifyUtil.Outcome.SUCCESS), Arrays.asList(certArray), certArray);
        return certArray;

    }

    /**
     * retrieve the issuers cedrtificate by searching it in the trust list
     * @param signCert the signers certificate
     * @param certOpt the certificate optional holding the issuer later on
     * @return the optional holding the found cdertificate
     */
    public Optional<X509Certificate> getX509IssuerCertificate(X509Certificate signCert, Optional<X509Certificate> certOpt)
    {

        for (TrustListManager walker : walkers) {
            certOpt = walker.getAllCerts()
                    .stream().filter(e -> {
                                try {
                                    RDN commonIssuer = ((Name) signCert.getIssuerDN()).element(ObjectID.commonName);
                                    String issuer = commonIssuer.getRFC2253String();
                                    RDN commonSubject = ((Name) e.getSubjectDN()).element(ObjectID.commonName);
                                    String subject = commonSubject.getRFC2253String();
                                    return issuer.equals(subject);
                                } catch (Exception ex) {
                                    return false;
                                }

                            })
                    .findFirst();
            if (certOpt.isPresent()) {
                break;
            }
        }
        return certOpt;
    }

    /**
     * This method checks the specified certificate chain with
     * OCSP
     * @param results the check results object
     * @param chain the certificate chain
     */
    public void checkOCSP (VerifyUtil.SignerInfoCheckResults results, X509Certificate [] chain) {
        try {
            boolean reqIsSigned = true;
            Tuple<PrivateKey, X509Certificate[]> bean = loadKey();
            X509Certificate[] certs;
            certs = bean.getSecond();
            int responseStatus = 0;
            String ocspUrl = HttpOCSPClient.getOCSPUrl(chain[0]);
            OCSPResponse response = null;
            if (reqIsSigned == true && ocspUrl != null) {
                response = HttpOCSPClient.sendOCSPRequest(ocspUrl, bean.getFirst(),
                        certs, chain, true, ReqCert.certID, false);
            } else if (ocspUrl != null){
                response = HttpOCSPClient.sendOCSPRequest(ocspUrl, null,
                        null, chain,true, ReqCert.certID, false);
            }

            if (response != null) {
                responseStatus = HttpOCSPClient.getClient().parseOCSPResponse(response, true);
                String resultName = chain[0].getSubjectDN().getName();
                if (responseStatus == OCSPResponse.successful) {
                    results.addOcspResult(resultName, new Tuple<String, VerifyUtil.Outcome>(response.getResponseStatusName(), VerifyUtil.Outcome.SUCCESS));
                } else if (responseStatus == OCSPResponse.tryLater) {
                    results.addOcspResult(resultName, new Tuple<String, VerifyUtil.Outcome>(response.getResponseStatusName(),
                            VerifyUtil.Outcome.UNDETERMINED));
                } else {
                    results.addOcspResult(resultName, new Tuple<String, VerifyUtil.Outcome>(response.getResponseStatusName(),
                            VerifyUtil.Outcome.FAILED));
                }
            }
        } catch (Exception ex){
            throw new IllegalStateException("OCSP check failed with exception", ex);
        }
    }

    public void checkSignatureAlgorithm(AlgorithmID sigAlg, PublicKey pubKey, VerifyUtil.SignerInfoCheckResults results) {
        if (pubKey instanceof RSAPublicKey) {
            RSAPublicKey pubKeyRSA = (RSAPublicKey)pubKey;
            checkRSAKeyAlg(pubKeyRSA, results);
            checkRSAPadding(sigAlg, results);
        } else if(pubKey instanceof DSAPublicKey) {

        } else if (pubKey instanceof AbstractECPublicKey) {

        }
    }

    public void checkDigestAlgorithm(AlgorithmID sigAlg, VerifyUtil.SignerInfoCheckResults results) {

    }

    public void checkRSAKeyAlg(RSAPublicKey pubKey, VerifyUtil.SignerInfoCheckResults results) {
        int lenght = pubKey.getModulus().bitLength();
        if (lenght >= 4096) {
            results.addSignatureResult("check signature algorithm", new Tuple<>("algorithm", VerifyUtil.Outcome.SUCCESS));
        } else {
            results.addSignatureResult("check signature algorithm", new Tuple<>("algorithm", VerifyUtil.Outcome.UNDETERMINED));
        }
    }

    public void checkRSAPadding(AlgorithmID sigAlg, VerifyUtil.SignerInfoCheckResults results) {
        if (sigAlg.equals(CMSAlgorithmID.rsassaPss)) {
            results.addSignatureResult("check rsa padding", new Tuple<>("padding PSS 2.1", VerifyUtil.Outcome.SUCCESS));
        } else {
            results.addSignatureResult("check rsa padding", new Tuple<>("padding PSS 1.5", VerifyUtil.Outcome.UNDETERMINED));
        }
    }



}
