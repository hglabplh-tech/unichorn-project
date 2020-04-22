package harry.security.responder.resources;

import iaik.asn1.structures.AlgorithmID;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.OCSPRequest;
import iaik.x509.ocsp.OCSPResponse;
import iaik.x509.ocsp.utils.ResponseGenerator;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.ocsp.HttpOCSPClient;
import org.harry.security.util.ocsp.OCSPClient;
import org.junit.Test;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.net.URL;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.util.*;

import static org.harry.security.util.HttpsChecker.loadKey;

public class ResponderTest {


    private static final String ALIAS = "Common T-Systems Green TeamUserRSA";

    @Test
    public void nativeCallerTest() throws Exception {
        List<X509Certificate> certList= new ArrayList<>();
        certList.add(new CertWriterReader().readFromFilePEM(
                ResponderTest.class.getResourceAsStream("/DeutscheTelekomAGIssuingCA01.crt")));
        certList.add(new X509Certificate(ResponderTest.class.getResourceAsStream("/hglabplh.cer")));
        Tuple<PrivateKey, X509Certificate> keys = null;

        InputStream keyStore = ResponderTest.class.getResourceAsStream("/application.jks");
        KeyStore store = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "JKS");
        keys = KeyStoreTool.getKeyEntry(store, ALIAS, "geheim".toCharArray());
        X509Certificate[] certs = new X509Certificate[2];
        certs[0] = keys.getSecond();
        certs[1] =  keys.getSecond();
                /*OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, bean.getSelectedKey(),
                        certs, certList.toArray(new X509Certificate[0]), false);*/
        int responseStatus = 0;
        for (X509Certificate cert : certList) {
            URL ocspUrl = HttpOCSPClient.getOCSPUrl(cert);
            ocspUrl= new URL("http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/ocsp");
            /*OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, keys.getFirst(),
                    certs, certList.toArray(new X509Certificate[0]), true); */
            OCSPClient client = new OCSPClient();
            OCSPRequest request = client.createOCSPRequest(null, null,
                    certList.toArray(new X509Certificate[0]), false);

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
    public void testOCSPOK() throws Exception {
        List<X509Certificate> certList= new ArrayList<>();
        certList.add(new CertWriterReader().readFromFilePEM(
                ResponderTest.class.getResourceAsStream("/DeutscheTelekomAGIssuingCA01.crt")));
        certList.add(new X509Certificate(ResponderTest.class.getResourceAsStream("/hglabplh.cer")));
        Tuple<PrivateKey, X509Certificate> keys = null;

            InputStream keyStore = ResponderTest.class.getResourceAsStream("/application.jks");
            KeyStore store = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "JKS");
            keys = KeyStoreTool.getKeyEntry(store, ALIAS, "geheim".toCharArray());
        X509Certificate[] certs = new X509Certificate[2];
        certs[0] = keys.getSecond();
        certs[1] =  keys.getSecond();
                /*OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, bean.getSelectedKey(),
                        certs, certList.toArray(new X509Certificate[0]), false);*/
        int responseStatus = 0;
        for (X509Certificate cert : certList) {
            URL ocspUrl = HttpOCSPClient.getOCSPUrl(cert);
            ocspUrl= new URL("http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/ocsp");
            /*OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, keys.getFirst(),
                    certs, certList.toArray(new X509Certificate[0]), true); */
            OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, null,
                    null, certList.toArray(new X509Certificate[0]), false);
            responseStatus = HttpOCSPClient.getClient().parseOCSPResponse(response, false);
        }

    }
}
