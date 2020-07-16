package org.harry.security.util;

import iaik.cms.SignerInfo;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.OCSPResponse;

import java.util.*;


public class VerificationResults {
    /**
     * The cheeck result codes
     */
    public  enum Outcome {
        SUCCESS,
        FAILED,
        INDETERMINED;
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
        Map<String, Tuple<String, Outcome>> formatResults = new HashMap<>();
        Map<String, Tuple<String, Outcome>> signatureResults = new HashMap<>();
        Map<String, Tuple<OCSPResponse, Outcome>> ocspResults = new HashMap<>();
        X509Certificate[] signerChain = null;
        SignerInfo info = null;
        Map<Tuple<String, Outcome>, List<X509Certificate>> signersChain = new HashMap<>();

        public void setInfo(SignerInfo info) {
            this.info = info;
        }

        public void addCertChain(Tuple<String, Outcome> result, List<X509Certificate> resultCerts, X509Certificate [] certChain) {
            signerChain = certChain;
            signersChain.put(result, resultCerts);
        }

        public SignerInfo getInfo() {
            return info;
        }

        public Map<Tuple<String, Outcome>, List<X509Certificate>> getSignersChain() {
            return signersChain;
        }

        public Map<String, Tuple<String, Outcome>> getFormatResult() {
            return formatResults;
        }

        public Map<String, Tuple<String, Outcome>> getSignatureResult() {
            return signatureResults;
        }

        public Map<String, Tuple<OCSPResponse, Outcome>> getOcspResult() {
            return ocspResults;
        }

        public X509Certificate [] getSignerChain() {
            return signerChain;
        }

        public SignerInfoCheckResults addSignatureResult(String resultName, Tuple<String, Outcome> signatureResult) {
            this.signatureResults.put(resultName, signatureResult);
            return this;
        }

        public SignerInfoCheckResults addFormatResult(String resultName, Tuple<String, Outcome> signatureResult) {
            this.formatResults.put(resultName, signatureResult);
            return this;
        }

        public SignerInfoCheckResults addOcspResult(String resultName, Tuple<OCSPResponse, Outcome> ocspResult) {
            this.ocspResults.put(resultName, ocspResult);
            return this;
        }

        public Outcome sigMathOk () {
            Tuple<String, Outcome> result = signatureResults.get("sigMathOk");
            if (result != null) {
                return result.getSecond();
            } else {
                return Outcome.FAILED;
            }
        }

        public Tuple<String, Outcome> getSignatureAlgorithm() {
            Tuple<String, Outcome> algName = signatureResults.get("sigAlg");
            Tuple<String, Outcome> resultCheck =  signatureResults.get("check_signature_algorithm");
            Tuple<String, Outcome> result = new Tuple<>(algName.getFirst(), resultCheck.getSecond());
            return result;
        }

        public Tuple<OCSPResponse, Outcome> getOCSPResult() {
            Tuple<OCSPResponse, Outcome> result = ocspResults.get("ocspResult");
            return result;
        }

        public Outcome checkFormatResult() {
            Outcome format = Outcome.SUCCESS;
            for (Map.Entry<String, Tuple<String, Outcome>> entry: formatResults.entrySet()) {
                Tuple<String, Outcome> toCheck = formatResults.get(entry.getKey());
                if (toCheck.getSecond() == Outcome.FAILED) {
                    format = Outcome.FAILED;
                }
            }
            return format;
        }

        public Outcome checkOverallResult () {
            Outcome overall = Outcome.SUCCESS;
            for (Map.Entry<String, Tuple<String, Outcome>> entry: formatResults.entrySet()) {
                Tuple<String, Outcome> toCheck = formatResults.get(entry.getKey());
                if (toCheck.getSecond() == Outcome.FAILED) {
                    overall = Outcome.FAILED;
                }
            }
            for (Map.Entry<String, Tuple<String, Outcome>> entry: signatureResults.entrySet()) {
                Tuple<String, Outcome> toCheck = signatureResults.get(entry.getKey());
                if (toCheck.getSecond() == Outcome.FAILED) {
                    overall = Outcome.FAILED;
                }
            }
            for (Map.Entry<String, Tuple<OCSPResponse, Outcome>> entry: ocspResults.entrySet()) {
                Tuple<OCSPResponse, Outcome> toCheck = ocspResults.get(entry.getKey());
                if (toCheck.getSecond() == Outcome.FAILED) {
                    overall = Outcome.FAILED;
                }
            }
            return overall;
        }
    }
}