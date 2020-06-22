package org.harry.security.util.mailer;

import org.apache.commons.net.PrintCommandListener;
import org.apache.commons.net.imap.IMAPClient;
import org.apache.commons.net.imap.IMAPSClient;
import org.apache.http.client.utils.URIBuilder;

import java.net.URI;

public class EMailConnector {

    public static final String T_ONLINE_IMAP_ADDR = "secureimap.t-online.de";
    public static final String T_ONLINE_SMTP_URI_HOST = "securesmtp.t-online.de";
    public static final String T_ONLINE_IMAP_URI_HOST = "secureimap.t-online.de";

    public static final int T_ONLINE_IMAP_PORT = 993;
    public static final int T_ONLINE_SMTP_PORT = 465;

    private final String imapHost;
    private final int port;

    public EMailConnector(final String imapHost, final int port) {
        this.imapHost = imapHost;
        this.port = port;
    }
    public IMAPSClient connect(String username, String password) {
        try {
            IMAPSClient client = IMAPUtils.imapLogin(imapHost, port, username, password, 100000, null);
            client.addProtocolCommandListener(new PrintCommandListener(System.out, true));
            client.setSoTimeout(6000);
            client.capability();
            client.select("inbox");
            client.examine("inbox");
            client.status("inbox", new String[]{"MESSAGES"});
            return client;
        } catch(Exception ex) {
            throw new IllegalStateException("IMAP Login failed", ex);
        }
    }
}
