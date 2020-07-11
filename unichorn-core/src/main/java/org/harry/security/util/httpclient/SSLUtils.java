package org.harry.security.util.httpclient;

import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.tinylog.Logger;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.*;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.harry.security.CommonConst.APP_DIR;
import static org.harry.security.CommonConst.isWindows;

public class SSLUtils {

    public static final String SSL = "SSL";
    public static final String TLS = "TLS";
    public static final String TLSV10 = "TLSv1.0";
    public static final String TLSV11 = "TLSv1.1";
    public static final String TLSV12 = "TLSv1.2";
    public static final String TLSV13 = "TLSv1.3";

    public static KeyStore readTrustStore() throws Exception {
        KeyStore keyStore = null;

        File cacerts = new File(APP_DIR, "trustCerts.p12");
        if (cacerts.exists()) {
            keyStore = KeyStoreTool.loadStore(new FileInputStream(cacerts),
                    "changeit".toCharArray(), "UnicP12");
        }
        return keyStore;
    }

    public static KeyStore readStore()  {
        return KeyStoreTool.loadAppStore();
    }

    public static SSLContext createStandardContext(String protocol) throws Exception {
        SSLContextBuilder builder = SSLContexts.custom().setProtocol(protocol);
        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String s, SSLSession sslSession) {
                return true;
            }
        });
        return builder
                .loadKeyMaterial(readStore(), "geheim".toCharArray())
                .loadTrustMaterial(readTrustStore(), null)
                .build();
    }

    public static SSLContext trustReallyAllShit() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509ExtendedTrustManager() {

                    @Override
                    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    @Override
                    public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {

                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {

                    }

                    @Override
                    public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {

                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {

                    }
                }
        };
        // Install the all-trusting trust manager
        try {
            SSLContext sc = SSLContext.getInstance("TLSv1.1");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            return sc;
        } catch (Exception ex) {
            throw new IllegalStateException("socket context init failed", ex);
        }


    }

    public static void installHttpHttpsProtocol() {
        // Install protocol.
        try {
            URL.setURLStreamHandlerFactory(new URLStreamHandlerFactory() {
                @Override
                public URLStreamHandler createURLStreamHandler(String protocol) {
                    if (protocol.equals("http")) {
                        URLStreamHandler handler = new URLStreamHandler() {

                            @Override
                            protected URLConnection openConnection(URL u) throws IOException {
                                return u.openConnection();
                            }
                        };
                        return handler;
                    } else if (protocol.equals("https")) {
                        URLStreamHandler handler = new URLStreamHandler() {

                            @Override
                            protected URLConnection openConnection(URL u) throws IOException {
                                try {
                                    SSLContext sslContext = null;
                                    if (SSLUtils.isHostLocal(u.getHost())) {
                                        sslContext = SSLUtils.trustReallyAllShit();
                                    } else {
                                        sslContext = SSLUtils.createStandardContext("TLS");
                                    }
                                    if (SSLUtils.isHostLocal(u.getHost())) {
                                        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
                                        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                                            @Override
                                            public boolean verify(String s, SSLSession sslSession) {
                                                return true;
                                            }
                                        });
                                        SSLContext.setDefault(sslContext);
                                    } else {
                                        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
                                        SSLContext.setDefault(sslContext);
                                    }
                                } catch(Exception ex) {
                                    throw new IOException(ex.getMessage());
                                }

                                return u.openConnection();
                            }
                        };
                        return handler;
                    }
                    return null;
                }
            });
        } catch (Throwable t) {
            if (!t.getMessage().contains("factory already defined")) {
                Logger.trace(" Error occurred : " + t.getMessage());
                Logger.trace(t);
            }
        }
    }

    public static boolean isHostLocal(String host) {
        return (("localhost".equals(host)) || ("127.0.0.1".equals(host)));
    }
}
