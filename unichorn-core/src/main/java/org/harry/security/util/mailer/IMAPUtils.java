/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.harry.security.util.mailer;

import java.io.IOException;
import java.net.Authenticator;
import java.net.Socket;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Properties;

import org.apache.commons.net.ProtocolCommandListener;
import org.apache.commons.net.imap.IMAPClient;
import org.apache.commons.net.imap.IMAPSClient;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.harry.security.util.httpclient.SSLUtils;

import javax.mail.Session;
import javax.mail.Store;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * Utility class for shared IMAP utilities
 */

class IMAPUtils {


    static Store imapLogin(final String host, final int port,
                                final String username,
                                String password,
                                final int defaultTimeout,
                                ProtocolCommandListener listener) throws Exception {

        // prompt for the password if necessary
        password = Utils.getPassword(username, password);

        final Session imap;


        TrustStrategy strategie = new TrustAllStrategy();
        SSLContext context =
                SSLUtils.createStandardContext();
        SSLContext.setDefault(context);
        Properties props = System.getProperties();
        props.setProperty("mail.store.protocol", "imaps");
        Session session = Session.getInstance(props, null);

        Store store = session.getStore("imaps");
        System.out.println("Using secure protocol");
        if (store != null) {
            store.connect(host, port, username, password);
        }

        return store;
    }

    public static TrustManager getEmailTrustAll() {
        TrustManager manager = new X509ExtendedTrustManager() {
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
        };
        return manager;
    }
}
