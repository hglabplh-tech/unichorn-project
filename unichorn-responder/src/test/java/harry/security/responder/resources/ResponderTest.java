package harry.security.responder.resources;

import iaik.x509.X509Certificate;
import iaik.x509.ocsp.OCSPResponse;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.ocsp.HttpOCSPClient;
import org.junit.Test;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import static org.harry.security.util.HttpsChecker.loadKey;

public class ResponderTest {

    @Test
    public void testOCSPOK() throws Exception {
        List<X509Certificate> certList= new ArrayList<>();
        certList.add(new CertWriterReader().readFromFilePEM(
                ResponderTest.class.getResourceAsStream("/DeutscheTelekomAGIssuingCA01.crt")));
        certList.add(new X509Certificate(ResponderTest.class.getResourceAsStream("/hglabplh.cer")));
        CertWriterReader.KeyStoreBean bean = loadKey();
        X509Certificate[] certs = new X509Certificate[2];
        certs[0] = bean.getSelectedCert();
        certs[1] = bean.getSelectedCert();
                /*OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, bean.getSelectedKey(),
                        certs, certList.toArray(new X509Certificate[0]), false);*/
        int responseStatus = 0;
        for (X509Certificate cert : certList) {
            URL ocspUrl = HttpOCSPClient.getOCSPUrl(cert);
            ocspUrl= new URL("http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/ocsp");
            OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, bean.getSelectedKey(),
                    certs, certList.toArray(new X509Certificate[0]), true);
            int oldStatus = responseStatus;
            responseStatus = HttpOCSPClient.getClient().parseOCSPResponse(response, true);
            if(oldStatus != OCSPResponse.successful) {
                responseStatus = oldStatus;
            }
        }

    }
}
