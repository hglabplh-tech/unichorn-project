package org.harry.security.util.ocsp;

import com.itextpdf.text.pdf.security.OcspClient;
import iaik.x509.ocsp.OCSPResponse;
import iaik.x509.ocsp.ReqCert;
import org.harry.security.util.Tuple;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.harry.security.CommonConst.OCSP_URL;
import static org.harry.security.util.HttpsChecker.loadKey;

public class UnichornOcspClient implements OcspClient {

    public UnichornOcspClient() {
    }

    @Override
    public byte[] getEncoded(X509Certificate userCert, X509Certificate rootCert, String url) {
        try {
            if (url == null) {
                url = OCSPCRLClient.getOCSPUrl(new iaik.x509.X509Certificate(userCert.getEncoded()));
            }
            if (url == null) {
                url = OCSP_URL;
            }
            Tuple<PrivateKey, iaik.x509.X509Certificate[]> keys = loadKey();
            iaik.x509.X509Certificate[] chain = new iaik.x509.X509Certificate[2];
            chain[0] = new iaik.x509.X509Certificate(userCert.getEncoded());
            chain[1] = new iaik.x509.X509Certificate(rootCert.getEncoded());
            OCSPResponse response = HttpOCSPClient.sendOCSPRequest(url, keys.getFirst(), keys.getSecond(), chain,
                    ReqCert.certID, false, true);
            return response.getEncoded();
        } catch (Exception ex) {
            throw new IllegalStateException("cannot send ocsp request", ex);
        }
    }
}
