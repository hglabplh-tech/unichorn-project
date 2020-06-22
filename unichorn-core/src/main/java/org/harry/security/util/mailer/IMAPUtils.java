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
import java.net.Socket;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.apache.commons.net.ProtocolCommandListener;
import org.apache.commons.net.imap.IMAPClient;
import org.apache.commons.net.imap.IMAPSClient;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * Utility class for shared IMAP utilities
 */

class IMAPUtils {

    /**
     * Parse the URI and use the details to connect to the IMAP(S) server and login.
     *
     * @param host the host of the imap service
     * @param port the port to connect to
     * @param username the username for login to imap
     * @param password the user pass for login
     * @param defaultTimeout initial timeout (in milliseconds)
     * @param listener for tracing protocol IO (may be null)
     * @return the IMAP client - connected and logged in
     * @throws IOException if any problems occur
     */
    static IMAPSClient imapLogin(final String host, final int port,
                                final String username,
                                String password,
                                final int defaultTimeout,
                                ProtocolCommandListener listener) throws IOException {

        // prompt for the password if necessary
        password = Utils.getPassword(username, password);

        final IMAPSClient imap;


        System.out.println("Using secure protocol");
        imap = new IMAPSClient(true); // implicit
        TrustManager manager = getEmailTrustAll();
        imap.setTrustManager(manager);

        if (port != -1) {
            imap.setDefaultPort(port);
        }

        imap.setDefaultTimeout(defaultTimeout);

        if (listener != null) {
            imap.addProtocolCommandListener(listener);
        }

        final String server = host;
        System.out.println("Connecting to server " + server + " on " + imap.getDefaultPort());

        try {
            imap.connect(server);
            System.out.println("Successfully connected");
        } catch (IOException e) {
            throw new RuntimeException("Could not connect to server.", e);
        }

        if (!imap.login(username, password)) {
            imap.disconnect();
            throw new RuntimeException("Could not login to server. Check login details.");
        }

        return imap;
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
