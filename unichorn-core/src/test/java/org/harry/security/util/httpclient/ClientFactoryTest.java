package org.harry.security.util.httpclient;

import iaik.protocol.https.HttpsURLConnection;
import org.junit.Test;

import java.net.URL;

public class ClientFactoryTest {

    @Test
    public void testreateIaikConn() throws Exception {
        HttpsURLConnection conn = ClientFactory.createIAIKManagedClient(new URL("https://www.google.de"));
        conn.getResponseCode();
        conn.getInputStream();
    }
}
