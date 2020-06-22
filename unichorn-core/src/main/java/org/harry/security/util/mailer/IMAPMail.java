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
import java.net.URI;

import org.apache.commons.net.PrintCommandListener;
import org.apache.commons.net.imap.IMAPClient;

public class IMAPMail
{

    public static void main(String[] args) throws IOException {
        if (args.length != 4)
        {
            System.err.println(
                "Usage: IMAPMail imap[s]://username:password@server/");
            System.err.println("Connects to server; lists capabilities and shows Inbox status");
            System.exit(1);
        }

        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String username = args[2];
        String password = args[3];

        // Connect and login
        final IMAPClient imap = IMAPUtils.imapLogin(host, port,username, password, 10000, null);

        // suppress login details
        imap.addProtocolCommandListener(new PrintCommandListener(System.out, true));

        try {
            imap.setSoTimeout(6000);

            imap.capability();

            imap.select("inbox");

            imap.examine("inbox");

            imap.status("inbox", new String[]{"MESSAGES"});

        } catch (IOException e) {
            System.out.println(imap.getReplyString());
            e.printStackTrace();
            System.exit(10);
            return;
        } finally {
            imap.logout();
            imap.disconnect();
        }
    }
}

/* kate: indent-width 4; replace-tabs on; */
