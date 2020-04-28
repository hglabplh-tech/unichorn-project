package harry.security.responder.resources;

import iaik.asn1.structures.AlgorithmID;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.OCSPRequest;
import iaik.x509.ocsp.OCSPResponse;
import iaik.x509.ocsp.ReqCert;
import iaik.x509.ocsp.utils.ResponseGenerator;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.harry.security.util.CertLoader;
import org.harry.security.util.HttpsChecker;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.ocsp.HttpOCSPClient;
import org.harry.security.util.ocsp.OCSPClient;
import org.junit.Test;

import javax.servlet.*;
import javax.servlet.http.*;
import javax.ws.rs.core.Response;
import java.io.*;
import java.net.URL;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.util.*;

import static org.harry.security.util.HttpsChecker.loadKey;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class ResponderTest {


    private static final String ALIAS = "Common T-Systems Green TeamUserRSA";

    @Test
    public void nativeCaller() throws Exception {
        List<X509Certificate> certList= new ArrayList<>();
        certList.add(new CertWriterReader().readFromFilePEM(
                ResponderTest.class.getResourceAsStream("/DeutscheTelekomAGIssuingCA01.crt")));
        certList.add(new X509Certificate(ResponderTest.class.getResourceAsStream("/hglabplh.cer")));
        Tuple<PrivateKey, X509Certificate[]> keys = null;

        InputStream
                keyStore = ResponderTest.class.getResourceAsStream("/application.jks");
        KeyStore store = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "JKS");
        keys = KeyStoreTool.getKeyEntry(store, ALIAS, "geheim".toCharArray());
        X509Certificate[] certs = new X509Certificate[2];
        certs = keys.getSecond();
                /*OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, bean.getSelectedKey(),
                        certs, certList.toArray(new X509Certificate[0]), false);*/
        int responseStatus = 0;
        for (X509Certificate cert : certList) {
            String ocspUrlOrig = HttpOCSPClient.getOCSPUrl(cert);
            URL ocspUrl= new URL("http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/ocsp");
            /*OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, keys.getFirst(),
                    certs, certList.toArray(new X509Certificate[0]), true); */
            OCSPClient client = new OCSPClient();
            OCSPRequest request = client.createOCSPRequest(null, null,
                    certList.toArray(new X509Certificate[0]),
                    false, ReqCert.certID, ocspUrlOrig);

            ByteArrayInputStream stream = new ByteArrayInputStream(request.getEncoded());
            ResponseGenerator respGen = null;
            AlgorithmID sigAlg =  null;
            Map<String, String> msg = new HashMap<>();
            OCSPResponse response = UnicHornResponderUtil.generateResponse(request,
                    stream, respGen, sigAlg, msg);
            client.parseOCSPResponse(response, false);

        }

    }

    @Test
    public void nativeCallerSigned() throws Exception {
        List<X509Certificate> certList= new ArrayList<>();
        certList.add(new CertWriterReader().readFromFilePEM(
                ResponderTest.class.getResourceAsStream("/DeutscheTelekomAGIssuingCA01.crt")));
        certList.add(new X509Certificate(ResponderTest.class.getResourceAsStream("/hglabplh.cer")));
        Tuple<PrivateKey, X509Certificate[]> keys = null;

        InputStream
                keyStore = ResponderTest.class.getResourceAsStream("/application.jks");
        KeyStore store = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "JKS");
        keys = KeyStoreTool.getKeyEntry(store, ALIAS, "geheim".toCharArray());
        X509Certificate[] certs = new X509Certificate[2];
        certs = keys.getSecond();
        for (X509Certificate cert : certList) {
            String ocspURL = HttpOCSPClient.getOCSPUrl(certList.get(0));
            OCSPClient client = new OCSPClient();
            OCSPRequest request = client.createOCSPRequest(keys.getFirst(),
                    certs, certList.toArray(new X509Certificate[0]),
                    false, ReqCert.pKCert, ocspURL);

            ByteArrayInputStream stream = new ByteArrayInputStream(request.getEncoded());
            ResponseGenerator respGen = null;
            AlgorithmID sigAlg =  null;
            Map<String, String> msg = new HashMap<>();
            OCSPResponse response = UnicHornResponderUtil.generateResponse(request,
                    stream, respGen, sigAlg, msg);
            client.parseOCSPResponse(response, false);

        }

    }

    @Test
    public void nativeCallerSigned2() throws Exception {
        checkHttpsCertValidity("https://www.digicert.com", true, true);
        List<X509Certificate[]> certList= new ArrayList<>();
        InputStream keystoreUser = ResponderTest.class.getResourceAsStream("/t-systems.jks");
        KeyStore tsystems = KeyStoreTool.loadStore(keystoreUser, "geheim".toCharArray(), "JKS");
        Enumeration<String> aliases = tsystems.aliases();
        while (aliases.hasMoreElements())  {
            String alias = aliases.nextElement();
            X509Certificate[] cert = KeyStoreTool.getCertChainEntry(tsystems, alias);
            certList.add(cert);
        }
        Tuple<PrivateKey, X509Certificate[]> keys = null;

        InputStream
                keyStore = ResponderTest.class.getResourceAsStream("/application.jks");
        KeyStore store = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "JKS");
        keys = KeyStoreTool.getKeyEntry(store, ALIAS, "geheim".toCharArray());
        X509Certificate[] certs = new X509Certificate[2];
        certs = keys.getSecond();
        for (X509Certificate[] certArray : certList) {
            if (certArray.length > 1) {
                String ocspURL = HttpOCSPClient.getOCSPUrl(certArray[0]);
                OCSPClient client = new OCSPClient();
                OCSPRequest request = client.createOCSPRequest(keys.getFirst(),
                        certs, certArray,
                        false, ReqCert.pKCert, ocspURL);

                ByteArrayInputStream stream = new ByteArrayInputStream(request.getEncoded());
                ResponseGenerator respGen = null;
                AlgorithmID sigAlg = null;
                Map<String, String> msg = new HashMap<>();
                OCSPResponse response = UnicHornResponderUtil.generateResponse(request,
                        stream, respGen, sigAlg, msg);
                client.parseOCSPResponse(response, false);
            }

        }

    }


    @Test
    public void testOCSPOK() throws Exception {
        List<X509Certificate> certList= new ArrayList<>();
        certList.add(new CertWriterReader().readFromFilePEM(
                ResponderTest.class.getResourceAsStream("/DeutscheTelekomAGIssuingCA01.crt")));
        certList.add(new X509Certificate(ResponderTest.class.getResourceAsStream("/hglabplh.cer")));
        Tuple<PrivateKey, X509Certificate[]> keys = null;

            InputStream keyStore = ResponderTest.class.getResourceAsStream("/application.jks");
            KeyStore store = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "JKS");

            keys = KeyStoreTool.getKeyEntry(store, ALIAS, "geheim".toCharArray());
        X509Certificate[] certs = new X509Certificate[2];
        certs = keys.getSecond();
                /*OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, bean.getSelectedKey(),
                        certs, certList.toArray(new X509Certificate[0]), false);*/
        int responseStatus = 0;
        for (X509Certificate cert : certList) {
            String ocspUrl = HttpOCSPClient.getOCSPUrl(cert);
            ocspUrl= "http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/ocsp";
            /*OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, keys.getFirst(),
                    certs, certList.toArray(new X509Certificate[0]), true); */
            OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, null,
                    null, certList.toArray(new X509Certificate[0]),
                    false, ReqCert.pKCert);
            responseStatus = HttpOCSPClient.getClient().parseOCSPResponse(response, false);
        }

    }

    @Test
    public void testOCSPOKSigned() throws Exception {
        List<X509Certificate> certList= new ArrayList<>();
        certList.add(new CertWriterReader().readFromFilePEM(
                ResponderTest.class.getResourceAsStream("/DeutscheTelekomAGIssuingCA01.crt")));
        certList.add(new X509Certificate(ResponderTest.class.getResourceAsStream("/hglabplh.cer")));
        Tuple<PrivateKey, X509Certificate[]> keys = null;

        InputStream keyStore = ResponderTest.class.getResourceAsStream("/application.jks");
        KeyStore store = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "JKS");

        keys = KeyStoreTool.getKeyEntry(store, ALIAS, "geheim".toCharArray());
        X509Certificate[] certs = new X509Certificate[2];
        certs = keys.getSecond();
        int responseStatus = 0;
        for (X509Certificate cert : certList) {
            String ocspUrl = HttpOCSPClient.getOCSPUrl(cert);
            ocspUrl= "http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/ocsp";
            OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, keys.getFirst(),
                    certs, certList.toArray(new X509Certificate[0]),
                    true, ReqCert.pKCert);
            responseStatus = HttpOCSPClient.getClient().parseOCSPResponse(response, false);
        }

    }

    @Test
    public void testOCSPOKSigned2() throws Exception {
        List<X509Certificate[]> certList= new ArrayList<>();
        InputStream keystoreUser = ResponderTest.class.getResourceAsStream("/t-systems.jks");
        KeyStore tsystems = KeyStoreTool.loadStore(keystoreUser, "geheim".toCharArray(), "JKS");
        Enumeration<String> aliases = tsystems.aliases();
        while (aliases.hasMoreElements())  {
            String alias = aliases.nextElement();
            X509Certificate[] cert = KeyStoreTool.getCertChainEntry(tsystems, alias);
            certList.add(cert);
        }
        Tuple<PrivateKey, X509Certificate[]> keys = null;

        InputStream
                keyStore = ResponderTest.class.getResourceAsStream("/application.jks");
        KeyStore store = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "JKS");
        keys = KeyStoreTool.getKeyEntry(store, ALIAS, "geheim".toCharArray());
        X509Certificate[] certs = new X509Certificate[2];
        certs = keys.getSecond();
        int responseStatus = 0;
        for (X509Certificate[] certArray : certList) {
            if (certArray.length > 1) {
                String ocspUrl =  HttpOCSPClient.getOCSPUrl(certArray[0]);
                ocspUrl = "http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/ocsp";
                OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, keys.getFirst(),
                        certs, certArray,
                        true, ReqCert.pKCert);
                responseStatus = HttpOCSPClient.getClient().parseOCSPResponse(response, false);
            }
        }

    }


    @Test
    public void testPutPKCS12Store() throws Exception {
        InputStream keyStore = ResponderTest.class.getResourceAsStream("/appKeyStore.jks");
        URL ocspUrl= new URL("http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/ocsp");
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = HttpClients.createDefault();
        System.out.println("Responder URL: " + ocspUrl.toString());
        HttpPut put = new HttpPut(ocspUrl.toURI());
        byte [] encoded = Base64.getEncoder().encode("geheim".getBytes());
        String encodeString = new String(encoded);
        put.setHeader("passwd",encodeString);
        put.setHeader("storeType", "JKS");
        HttpEntity entity = new InputStreamEntity(keyStore);
        put.setEntity(entity);
        CloseableHttpResponse response = httpClient.execute(put);
        assertThat(response.getStatusLine().getStatusCode(),
                is(Response.Status.CREATED.getStatusCode()));
    }

    public static Tuple<Integer, List<X509Certificate>> checkHttpsCertValidity(String checkURL,
                                                                               boolean ocspCheck,
                                                                               boolean altResponder
    ) {
        try {
            InputStream
                    keyStore = ResponderTest.class.getResourceAsStream("/application.jks");
            KeyStore store = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "JKS");
            Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getKeyEntry(store, ALIAS, "geheim".toCharArray());
            X509Certificate[] certs = new X509Certificate[2];
            certs = keys.getSecond();
            List<X509Certificate> certList = HttpsChecker.getCertFromHttps(checkURL);
            Map<String, X509Certificate> certMap = CertLoader.loadCertificatesFromWIN();
            boolean success = HttpsChecker.checkCertChain(certList, certMap);
            if (success) {
                System.out.println("found certificate in store");
                if (ocspCheck) {

                    Tuple<PrivateKey, X509Certificate[]> bean = loadKey();

                /*OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, bean.getSelectedKey(),
                        certs, certList.toArray(new X509Certificate[0]), false);*/
                    int responseStatus = 0;
                    for (X509Certificate cert : certList) {
                        String ocspUrlOrig = HttpOCSPClient.getOCSPUrl(cert);

                        if (altResponder) {
                            String ocspUrl ="http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/ocsp";
                        }
                        OCSPResponse response;
                        OCSPClient client = new OCSPClient();
                        if (true) {
                            OCSPRequest request = client.createOCSPRequest(keys.getFirst(),
                                    certs,
                                    certList.toArray(new X509Certificate[0]),
                                    true, ReqCert.certID, ocspUrlOrig);

                            ByteArrayInputStream stream = new ByteArrayInputStream(request.getEncoded());
                            ResponseGenerator respGen = null;
                            AlgorithmID sigAlg =  null;
                            Map<String, String> msg = new HashMap<>();
                            response = UnicHornResponderUtil.generateResponse(request,
                                    stream, respGen, sigAlg, msg);
                        }
                        int oldStatus = responseStatus;
                        responseStatus = client.parseOCSPResponse(response, true);
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
}
