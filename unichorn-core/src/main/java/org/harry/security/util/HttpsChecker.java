package org.harry.security.util;

import iaik.security.ssl.SSLClientContext;
import iaik.security.ssl.SSLContext;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.X509ExtensionInitException;
import iaik.x509.ocsp.*;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.ocsp.HttpOCSPClient;
import org.harry.security.util.ocsp.OCSPCRLClient;

import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

import static org.harry.security.CommonConst.*;
import static org.harry.security.util.ocsp.OCSPCRLClient.checkCertificateForRevocation;

public class HttpsChecker {

    public static final String PEER_CERTIFICATES = "PEER_CERTIFICATES";

    public static final String ALIAS = "Common T-Systems ImageMasterUserRSA";


    /**
     * Get a SSL certificate from a HttpClient Connection
     * @param urlString the URL as string
     * @return return the list of certificates
     */
    public static Tuple<ServerInfoGetter.CertStatusValue, List<X509Certificate>> getCertFromHttps(String urlString) {
        try {
            ServerInfoGetter.CertStatusValue result;
            List<X509Certificate> certList = new ArrayList<>();
            URL url = new URL(urlString);
            int port;
            if (url.getPort() != -1) {
                port = url.getPort();
            } else {
                port = 443;
            }
            ServerInfoGetter getter =
                    new ServerInfoGetter(url.getHost(), port);
            Hashtable<X509Certificate, X509Certificate[]> certsTable =
                    getter.getInformation();
            SSLClientContext context = getter.freshContext();
            result = getter.ocspCheckStapling(url.getHost(), port, context);
            Enumeration<X509Certificate[]> elements = certsTable.elements();
            if (elements.hasMoreElements()) {
                X509Certificate[] chain = elements.nextElement();
                for (X509Certificate certificate: chain) {
                    certList.add(certificate);
                }
            }
            return new Tuple<ServerInfoGetter.CertStatusValue, List<X509Certificate>>(result, certList);
        } catch (Throwable ex) {
                System.out.println("SSL error");
                ex.printStackTrace();
                throw new IllegalStateException("http error ", ex);
        }

    }
    // create http response certificate interceptor

    /**
     *
     * @param certList the retrieved certificate list
     * @param certMap the MAp containing the issuers
     * @return the check was positive
     */
    public static boolean checkCertChain(List<X509Certificate> certList, Map<String, X509Certificate> certMap
    ) {
        int counter = 0;
        X509Certificate successCert = null;
         for(X509Certificate certUsed : certList) {
             List<X509Certificate> allCerts = new ArrayList<>();
             allCerts.addAll(certMap.values());
             Optional<X509Certificate> certOpt  = allCerts.stream().filter(e ->
                     e.getIssuerDN().getName().equals(certUsed.getIssuerDN().getName())).findFirst();
             if  (certOpt.isPresent()) {
                 PublicKey pubKey = certOpt.get().getPublicKey();
                 try {
                     certUsed.verify(pubKey);
                     successCert = certUsed;
                 } catch (CertificateException e) {
                     e.printStackTrace();
                 } catch (NoSuchAlgorithmException e) {
                     e.printStackTrace();
                 } catch (InvalidKeyException e) {
                     e.printStackTrace();
                 } catch (NoSuchProviderException e) {
                     e.printStackTrace();
                 } catch (SignatureException e) {
                     e.printStackTrace();
                 }
                 counter++;
             }
         }
         if (successCert != null) {
             return true;
         }
         return false;
    }

    /**
     * This method is the one we call from outside to do a certificate check for
     * a given URL
     * @param checkURL the URL to check as string
     * @param ocspCheck do a check via OCSP
     * @param altResponder use our responder
     * @return a Tuple with the check rersult
     */
    public static Tuple<Integer, List<X509Certificate>> checkHttpsCertValidity(String checkURL,
                                                                               boolean ocspCheck,
                                                                               boolean altResponder
    ) {
        int responseStatus = -1;
        try {
        Tuple<ServerInfoGetter.CertStatusValue, List<X509Certificate>> result = HttpsChecker.getCertFromHttps(checkURL);
        Map<String, X509Certificate> certMap = CertLoader.loadCertificatesFromWIN();
        boolean success = HttpsChecker.checkCertChain(result.getSecond(), certMap);
        if (success) {
            System.out.println("found certificate in store");
            if (ocspCheck) {
                if (result.getFirst().equals(ServerInfoGetter.CertStatusValue.STATUS_OK)) {
                    return  new Tuple<Integer, List<X509Certificate>>(0, result.getSecond());
                } else if (result.getFirst().equals(ServerInfoGetter.CertStatusValue.STATUS_NOK)) {
                    return  new Tuple<Integer, List<X509Certificate>>(-1, result.getSecond());
                }

                Tuple<PrivateKey, X509Certificate[]> bean = loadKey();
                X509Certificate[] certs = new X509Certificate[2];
                certs = bean.getSecond();
                /*OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, bean.getSelectedKey(),
                        certs, certList.toArray(new X509Certificate[0]), false);*/

                for (X509Certificate cert : result.getSecond()) {
                    if (!CertificateWizzard.isCertificateSelfSigned(cert)) {
                        String ocspUrl = OCSPCRLClient.getOCSPUrl(cert);

                        if (altResponder) {
                            ocspUrl = OCSP_URL;
                        }
                        OCSPResponse response;

                        X509Certificate [] realChain = Util.arrangeCertificateChain(
                                result.getSecond().toArray(new X509Certificate[0]),
                                false);
                        response = HttpOCSPClient.sendOCSPRequest(ocspUrl, bean.getFirst(),
                                certs, realChain,
                                ReqCert.certID,
                                false, true);



                        responseStatus = HttpOCSPClient.getClient().parseOCSPResponse(response, true);

                        if (responseStatus == OCSPResponse.successful) {
                            BasicOCSPResponse basic = (BasicOCSPResponse) response.getResponse();
                            SingleResponse single = basic.getSingleResponses()[0];
                            responseStatus = single.getCertStatus().getCertStatus();
                            collectUsedResponders(cert, response.getResponseStatusName(), single.getCertStatus().getCertStatusName());
                        } else {
                            collectUsedResponders(cert, response.getResponseStatusName(), null);
                        }
                    }
                }

                if (responseStatus != 0) {
                    System.out.println("Check certificates via CRL");
                    X509Certificate [] certificates = new X509Certificate[result.getSecond().size()];
                    int index = 0;
                    for (X509Certificate cert : result.getSecond()) {
                        certificates[index] = cert;
                        index++;
                    }
                    boolean ok = checkCertificateForRevocation(certificates);
                    responseStatus = (ok) ? 0: -1;
                    System.out.println("Checked certificates via CRL ended with: " + responseStatus);
                }

                return  new Tuple<Integer, List<X509Certificate>>(Integer.valueOf(responseStatus), result.getSecond());
            } else {
                return new Tuple<Integer, List<X509Certificate>>(Integer.valueOf(OCSPResponse.successful), result.getSecond());
            }


        } else {
            return new Tuple<Integer, List<X509Certificate>>(Integer.valueOf(OCSPResponse.malformedRequest),
                    Collections.EMPTY_LIST);
        }
        } catch (Exception ex) {
            return new Tuple<Integer, List<X509Certificate>>(Integer.valueOf(OCSPResponse.tryLater),
                    Collections.EMPTY_LIST);
        }

    }

    public static String extractCNFromCert(X509Certificate cert) {
        Principal subjectDN = cert.getSubjectDN();
        return subjectDN.getName();
    }

    public static Tuple<PrivateKey, X509Certificate[]> loadKey() throws FileNotFoundException {


        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        return keys;
    }

    /**
     * This method collects ocsp-responders in relation to the requested certificates and the ocsp-response
     * to see what the different responders are doing and if they accept our requests
     * @param certificate the certificate requested
     * @param responseStatusName the name of the OCSP response status
     */
    public static void collectUsedResponders(X509Certificate certificate, String responseStatusName, String certificateState) {
        File usedRespondersFile = new File(APP_DIR, PROP_RESPONDER_LIST_FILE);
        try {
            String url = OCSPCRLClient.getOCSPUrl(certificate);
            if (url != null && !url.isEmpty()) {
                FileOutputStream out  = new FileOutputStream(usedRespondersFile, true);
                PrintWriter writer = new PrintWriter(out);
                writer.println("------ start entry ------");
                writer.println(certificate.getSubjectDN().getName());
                writer.println(url);
                writer.println(responseStatusName);
                if (certificateState != null) {
                    writer.println(certificateState);
                }
                writer.println("------ end entry ------");
                writer.flush();
                writer.close();
            }
        } catch (IOException | X509ExtensionInitException ex) {
           throw new IllegalStateException("Internal error getting OCSP Responder URL", ex);
        }

    }
}
