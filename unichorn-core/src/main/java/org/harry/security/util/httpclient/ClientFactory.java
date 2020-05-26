package org.harry.security.util.httpclient;

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
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.TrustStrategy;
import org.harry.security.util.certandkey.KeyStoreTool;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class ClientFactory {

    public static final String PEER_CERTIFICATES = "PEER_CERTIFICATES";

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
    createSSLClient() throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        SSLContextBuilder builder = SSLContexts.custom();
        builder.loadTrustMaterial(null, new TrustStrategy() {
            @Override
            public boolean isTrusted(java.security.cert.X509Certificate[] x509Certificates, String s) throws CertificateException {
                return true;
            }


        });
        SSLContext sslContext = builder
                .loadKeyMaterial(readStore(), "geheim".toCharArray())
                .build();
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

    private static KeyStore readStore()  {
        return KeyStoreTool.loadAppStore();
    }

}
