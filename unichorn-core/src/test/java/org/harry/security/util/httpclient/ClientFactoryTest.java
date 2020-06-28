package org.harry.security.util.httpclient;

import iaik.protocol.https.HttpsURLConnection;
import iaik.x509.X509Certificate;
import org.apache.commons.io.IOUtils;
import org.harry.security.testutils.TestBase;
import org.harry.security.util.ServerInfoGetter;
import org.junit.Test;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Hashtable;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class ClientFactoryTest extends TestBase {

    @Test
    public void testreateIaikConn() throws Exception {
        HttpsURLConnection conn = ClientFactory.createIAIKManagedClient(new URL("https://www.google.de"));
        conn.getResponseCode();
        conn.getInputStream();
    }

    @Test
    public void localHostConnectionSSL() throws Exception {
        SSLContext sslContext = SSLUtils.createStandardContext("TLS");
        SSLContext.setDefault(sslContext);
        javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String s, SSLSession sslSession) {
                return true;
            }
        });
        URL localhost = new URL("https://localhost");
        ServerInfoGetter getter = new ServerInfoGetter(localhost.getHost(), 443);
        Hashtable<X509Certificate, X509Certificate[]> certsTable = getter.getInformation();
        javax.net.ssl.HttpsURLConnection conn= (javax.net.ssl.HttpsURLConnection) localhost.openConnection();
        int code = conn.getResponseCode();
        assertThat(code, is(200));
        InputStream result = conn.getInputStream();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        IOUtils.copy(result, System.out);
    }
}
