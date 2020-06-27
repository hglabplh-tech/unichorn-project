package org.harry.security.util.mailer;

import org.apache.commons.net.imap.IMAPClient;
import org.apache.commons.net.imap.IMAPSClient;
import org.harry.security.testutils.TestBase;
import org.harry.security.util.Tuple;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pmw.tinylog.Configurator;
import org.pmw.tinylog.Level;
import org.pmw.tinylog.Logger;
import org.pmw.tinylog.writers.ConsoleWriter;
import org.pmw.tinylog.writers.FileWriter;

import javax.mail.Folder;
import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Store;
import java.io.File;
import java.net.URI;
import java.net.URL;
import java.util.Locale;

import static org.harry.security.util.mailer.EMailConnector.*;

public class EMailConnectorTest extends TestBase {

    @BeforeClass
    public static void initClass() {
        Configurator.defaultConfig()
                .writer(new ConsoleWriter())
                .locale(Locale.GERMANY)
                .level(Level.TRACE)
                .activate();
    }
    @Test
    public void connectSendReceiveMailDisconnect() throws Exception {
        Tuple<Store, Folder> connectResult = null;
        try {
            URL htmlURL = EMailConnectorTest.class.getResource("/data/mail.html");
            File htmlFile = new File(htmlURL.toURI());
            EMailConnector connector = new EMailConnector(T_ONLINE_IMAP_URI_HOST, T_ONLINE_IMAP_PORT);
            String password = System.getenv("emailpass");
            connectResult = connector.connect("harald.glab-plhak@t-online.de", password);
            ESender sender = ESender.newBuilder(connectResult.getFirst(), connectResult.getSecond(),
                    T_ONLINE_SMTP_URI_HOST,
                    Integer.toString(T_ONLINE_SMTP_PORT))
                    .addTo("heike.glab@t-online.de")
                    .addTo("juliane.glab@gmx.de")
                    .setFrom("harald.glab-plhak@t-online.de")
                    .setSubject("Hey people...")
                    .setText("I will inform you abaut sending this mail :rofl:. This is a test mail from a new mail client." +
                            "\nBest regards\n\nHarald Glab-Plhak")
                    .addAttachement(htmlFile)
                    .build();
            sender.sendSigned("harald.glab-plhak@t-online.de", password);
            sender = ESender.newBuilder(connectResult.getFirst(), connectResult.getSecond(),
                    T_ONLINE_SMTP_URI_HOST,
                    Integer.toString(T_ONLINE_SMTP_PORT))
                    .addTo("harald.glab-plhak@t-online.de")
                    .setFrom("harald.glab-plhak@t-online.de")
                    .setSubject("Hey people...")
                    .setText("I will inform you abaut sending this mail :rofl:. This is a test mail from a new mail client." +
                            "\nBest regards\n\nHarald Glab-Plhak")
                    .addAttachement(htmlFile)
                    .build();
            sender.sendSignedAndEncrypted("harald.glab-plhak@t-online.de", password);
            EReceiver receiver = new EReceiver(connectResult);
            Message[] messages = receiver.receiveMails();
            for (Message msg: messages) {
                System.out.println("From: " + msg.getFrom()[0].toString() + " Subject: " + msg.getSubject());
            }
            Message message = receiver.openMail("INBOX", messages, (messages.length -1));
            Logger.trace("message found content type is: " + message.getContentType());
        } catch(Exception ex) {

        } finally {
            if (connectResult != null) {
                if (connectResult.getFirst() != null) {
                    Store store = connectResult.getFirst();
                    store.close();
                }
            }
        }
    }
}
