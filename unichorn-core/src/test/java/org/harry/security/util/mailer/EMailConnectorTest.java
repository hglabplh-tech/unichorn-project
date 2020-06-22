package org.harry.security.util.mailer;

import org.apache.commons.net.imap.IMAPClient;
import org.apache.commons.net.imap.IMAPSClient;
import org.junit.Test;

import java.net.URI;

import static org.harry.security.util.mailer.EMailConnector.*;

public class EMailConnectorTest {

    @Test
    public void connectDisconnect() throws Exception {
        EMailConnector connector = new EMailConnector(T_ONLINE_IMAP_URI_HOST, T_ONLINE_IMAP_PORT);
        IMAPSClient client = connector.connect("harald.glab-plhak@t-online.de", "2Much4Me#");
        ESender sender = new ESender(T_ONLINE_SMTP_URI_HOST, T_ONLINE_SMTP_PORT);
        //sender.sendViaSmtp("harald.glab-plhak@t-online.de", "heike.glab@t-online.de", "Love Love Love");
    //    sender.sendEmail("harald.glab-plhak@t-online.de", "2Much4Me#");
        EReceiver receiver = new EReceiver(client);
        String message = receiver.receiveMails();
        System.out.println(message);
        String email = receiver.openMail("inbox", 9);
        System.out.println(email);
        client.disconnect();

    }
}
