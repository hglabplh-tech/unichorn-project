package org.harry.security.util;

import iaik.x509.X509Certificate;
import iaik.x509.ocsp.OCSPResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.apache.http.ssl.SSLContextBuilder;
import org.harry.security.util.httpclient.ClientFactory;
import org.harry.security.util.ocsp.HttpOCSPClient;

import javax.net.ssl.SSLContext;
import java.io.FileNotFoundException;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;

public class HttpsChecker {

    public static final String PEER_CERTIFICATES = "PEER_CERTIFICATES";


    public static List<X509Certificate> getCertFromHttps(String urlString) {
        List<X509Certificate> certList = new ArrayList<>();
        CloseableHttpClient httpClient = null;
        try {
            URL netURL = new URL(urlString);
            String protocol = netURL.getProtocol();
            if (!protocol.equalsIgnoreCase("https")) {
                //return certList;
            }
            // create closable http client and assign the certificate interceptor
            httpClient = ClientFactory.getAcceptCookieHttpClient();

            // make HTTP GET request to resource server
            HttpGet request = new HttpGet(netURL.toURI());
            System.out.println("Executing request " + request.getRequestLine());

            // create http context where the certificate will be added
            HttpContext context = new HttpCoreContext();
            SSLContext sslContext = SSLContextBuilder
                    .create()
                    .loadTrustMaterial(new TrustAllStrategy())
                    .build();
            httpClient.execute(request, context);

            // obtain the server certificates from the context
            Certificate[] peerCertificates = (Certificate[])context.getAttribute(PEER_CERTIFICATES);


            // loop over certificates and print meta-data
            for (Certificate certificate : peerCertificates){
                X509Certificate real = new X509Certificate(certificate.getEncoded());
                System.out.println(real.toString(true));
                certList.add(real);
            }


            return certList;
        } catch (Throwable ex) {
            System.out.println("http error");
            ex.printStackTrace();
            throw new IllegalStateException("http error ", ex);

        }
        finally {
            if (httpClient != null) {
                try {
                    httpClient.close();
                } catch (Exception ex) {
                    throw new IllegalStateException("http error ", ex);
                }

            }
        }

    }
    // create http response certificate interceptor

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

    public static Tuple<Integer, List<X509Certificate>> checkHttpsCertValidity(String checkURL,

                                                                               boolean ocspCheck) {
        try {
        List<X509Certificate> certList = HttpsChecker.getCertFromHttps(checkURL);
        Map<String, X509Certificate> certMap = CertLoader.loadCertificatesFromWIN();
        boolean success = HttpsChecker.checkCertChain(certList, certMap);
        if (success) {
            System.out.println("found certificate in store");
            if (ocspCheck) {

                SigningUtil.KeyStoreBean bean = loadKey();
                X509Certificate[] certs = new X509Certificate[2];
                certs[0] = bean.getSelectedCert();
                certs[1] = bean.getSelectedCert();
                /*OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, bean.getSelectedKey(),
                        certs, certList.toArray(new X509Certificate[0]), false);*/
                int responseStatus = 0;
                for (X509Certificate cert : certList) {
                    URL ocspUrl = HttpOCSPClient.getOCSPUrl(cert);
                    //ocspUrl= new URL("http://ocsp.digicert.com");
                    OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, bean.getSelectedKey(),
                            certs, certList.toArray(new X509Certificate[0]), true);
                    int oldStatus = responseStatus;
                    responseStatus = HttpOCSPClient.getClient().parseOCSPResponse(response, true);
                    if(oldStatus != OCSPResponse.successful) {
                        responseStatus = oldStatus;
                    }
                }

                return  new Tuple<Integer, List<X509Certificate>>(Integer.valueOf(responseStatus), certList);
            } else {
                return new Tuple<Integer, List<X509Certificate>>(Integer.valueOf(OCSPResponse.successful), certList);
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

    public static SigningUtil.KeyStoreBean loadKey() throws FileNotFoundException {

        return SigningUtil.loadSecrets(null, "JKS",
                "geheim", "RSA_MASTER");
    }

}
