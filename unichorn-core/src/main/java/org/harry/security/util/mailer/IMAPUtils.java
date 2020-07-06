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
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import org.apache.commons.net.ProtocolCommandListener;
import org.apache.commons.net.imap.IMAPClient;
import org.apache.commons.net.imap.IMAPSClient;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.bouncycastle.jcajce.provider.symmetric.TLSKDF;
import org.harry.security.util.Tuple;
import org.harry.security.util.httpclient.SSLUtils;
import org.pmw.tinylog.Logger;

import javax.mail.Folder;
import javax.mail.Session;
import javax.mail.Store;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * Utility class for shared IMAP utilities
 */

public class IMAPUtils {

    // "TLSv1.3"
    public static final String PROTOCOL = SSLUtils.TLSV11;

    public static final List<String> sentNamePatterns = Arrays.asList("Sent", "Gesendet");

    static Tuple<Session, Store> imapLogin(final String host, final int port,
                           final String username,
                           String password,
                           final int defaultTimeout,
                           ProtocolCommandListener listener) throws Exception {

        // prompt for the password if necessary
        password = Utils.getPassword(username, password);

        final Session imap;



        SSLContext context =
                SSLUtils.createStandardContext(PROTOCOL);
        SSLContext.setDefault(context);
        Properties props = System.getProperties();
        props.setProperty("mail.store.protocol", "imaps");
        Session session = Session.getInstance(props, null);
        Store store = session.getStore("imaps");
        System.out.println("Using secure protocol");
        if (store != null) {
            store.connect(host, port, username, password);
        }

        return new Tuple<>(session, store);
    }

    public static Folder[] listFolders(Tuple<Store, Folder> params, String emeil) {
        try {
            if (emeil.endsWith("t-online.de")) {
                Folder defaultFolder = params.getSecond();
                Folder[] temp = defaultFolder.list();
                Folder [] result = new Folder[temp.length + 1];
                int index = 0;
                for (; index < temp.length; index++) {
                    result[index] = temp[index];
                }
                result[index] = defaultFolder;
                return result;
            } else {
                Folder[] temp = params.getFirst().getDefaultFolder().list();
                return temp;
            }
        } catch  (Exception ex) {
            throw new IllegalStateException("cannot list the folders", ex);
        }
    }

    static String getProtocol(String email) {
        String protocol;
        if (email.endsWith("t-online.de")) {
            protocol = "SSL";
        } else {
            protocol = "TLS";
        }
        return protocol;
    }

    public static Folder getSentFolder(Store store, String email) {
        Folder sentFolder = null;
        String sentFolderName = null;
        if (email.endsWith("t-online.de")) {
            sentFolderName = "INBOX.Sent";
        } else {
            try {
                Folder defaultFolder = store.getDefaultFolder();
                Folder[] folders = defaultFolder.list();
                for (Folder folder:folders) {
                    if (sentNamePatterns.contains(folder.getFullName())) {
                        Logger.trace("Folder: " + folder.getFullName() + " found");
                        sentFolderName = folder.getFullName();
                        sentFolder = folder;
                    }
                    Logger.trace(folder.getFullName());

                }
            } catch (Exception ex) {

            }

        }
        try {
            if (sentFolder == null) {
                if (sentFolderName != null) {
                    sentFolder = store.getFolder(sentFolderName);
                } else {
                    return null;
                }
            }
        } catch (Exception ex) {
            sentFolder = null;
        }
        return sentFolder;
    }
}
