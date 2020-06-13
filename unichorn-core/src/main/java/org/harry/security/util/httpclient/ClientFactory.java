package org.harry.security.util.httpclient;

import iaik.protocol.https.HttpsURLConnection;
import iaik.security.ssl.SSLClientContext;
import org.apache.http.Header;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.ManagedHttpClientConnection;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HttpCoreContext;
import org.apache.http.ssl.SSLContextBuilder;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;

public class ClientFactory {

    public static final String PEER_CERTIFICATES = "PEER_CERTIFICATES";

    public static HttpsURLConnection createIAIKManagedClient(URL conURL) throws IOException {

        iaik.security.ssl.SSLContext context = new SSLClientContext();
        HttpsURLConnection connection = new HttpsURLConnection(conURL);
        connection.connect();
        connection.setSSLContext(context);
        connection.setDoInput(true);
        connection.setDoInput(true);
        return connection;
    }

    public static javax.net.ssl.HttpsURLConnection createURLConnection(URL conURL) throws IOException {


            javax.net.ssl.HttpsURLConnection connection = (javax.net.ssl.HttpsURLConnection) conURL.openConnection();
            //connection.setSSLSocketFactory(context.getSocketFactory());
            connection.setDoInput(true);
            connection.setDoInput(true);
            return connection;




    }

    /**
     * create a client accepting all requests from any host
     * @return the client
     */
    public static HttpClient getAcceptAllHttpClient() {
        try {

            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            SSLContext sslContext = SSLContextBuilder
                    .create()
                    .loadTrustMaterial(new TrustAllStrategy())
                    .build();

            // we can optionally disable hostname verification.
            // if you don't want to further weaken the security, you don't have to include this.
            HostnameVerifier allowAllHosts = new NoopHostnameVerifier();

            // create an SSL Socket Factory to use the SSLContext with the trust self signed certificate strategy
            // and allow all hosts verifier.
            SSLConnectionSocketFactory connectionFactory = new SSLConnectionSocketFactory(sslContext, allowAllHosts);
            return HttpClients
                    .custom()
                    .setSSLSocketFactory(connectionFactory)
                    .build();
        } catch (Exception e) {
            return HttpClients.createDefault();
        }
    }

    public static CloseableHttpClient getAcceptCookieHttpClient() {
        HttpResponseInterceptor certificateInterceptor = (httpResponse, context) -> {
            ManagedHttpClientConnection routedConnection =
                    (ManagedHttpClientConnection)context.getAttribute(HttpCoreContext.HTTP_CONNECTION);
            SSLSession sslSession = routedConnection.getSSLSession();
            if (sslSession != null) {

                // get the server certificates from the {@Link SSLSession}
                Certificate[] certificates = sslSession.getPeerCertificates();

                // add the certificates to the context, where we can later grab it from
                context.setAttribute(PEER_CERTIFICATES, certificates);
            }
        };
        HttpResponseInterceptor headerInterceptor = (httpResponse, context) -> {
            for (Header header: httpResponse.getAllHeaders()) {
                httpResponse.removeHeader(header);
            }
        };
        try {

            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            SSLContext sslContext = SSLContextBuilder
                    .create()
                    .loadTrustMaterial(new TrustAllStrategy())
                    .build();

            // we can optionally disable hostname verification.
            // if you don't want to further weaken the security, you don't have to include this.
            HostnameVerifier allowAllHosts = new NoopHostnameVerifier();

            // create an SSL Socket Factory to use the SSLContext with the trust self signed certificate strategy
            // and allow all hosts verifier.
            SSLConnectionSocketFactory connectionFactory = new SSLConnectionSocketFactory(sslContext, allowAllHosts);
            CookieStore store = new BasicCookieStore();
            return HttpClientBuilder.create()
                    .addInterceptorLast(certificateInterceptor)
                    .addInterceptorFirst(headerInterceptor)
                    .setDefaultCookieStore(store)
                    .setSSLSocketFactory(connectionFactory)
                    .build();
        } catch (Exception e) {
            return HttpClients.createDefault();
        }
    }

    public static CloseableHttpClient
    createSSLClient() throws Exception {
        SSLContext sslContext = SSLUtils.createStandardContext();
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                sslContext, new X509HostnameVerifier() {


            @Override
            public void verify(String s, java.security.cert.X509Certificate x509Certificate) throws SSLException {

            }



            @Override
            public void verify(String s, SSLSocket sslSocket) throws IOException {

            }

            @Override
            public void verify(String host, String[] cns,
                               String[] subjectAlts) throws SSLException {
            }

            @Override
            public boolean verify(String s, SSLSession sslSession) {
                return true;
            }
        });



        CloseableHttpClient httpclient = HttpClients.custom()
                .setSSLSocketFactory(sslsf).build();
        return httpclient;
    }


}
