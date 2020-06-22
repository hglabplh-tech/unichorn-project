package org.harry.security.util.mailer;

import org.apache.commons.net.imap.IMAPClient;
import org.apache.commons.net.imap.IMAPSClient;
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
import java.net.URI;
import java.util.Locale;

import static org.harry.security.util.mailer.EMailConnector.*;

public class EMailConnectorTest {

    @BeforeClass
    public static void initClass() {
        Configurator.defaultConfig()
                .writer(new ConsoleWriter())
                .locale(Locale.GERMANY)
                .level(Level.TRACE)
                .activate();
    }
    @Test
    public void connectDisconnect() throws Exception {
        Tuple<Store, Folder> connectResult = null;
        try {
            EMailConnector connector = new EMailConnector(T_ONLINE_IMAP_URI_HOST, T_ONLINE_IMAP_PORT);
            String password = System.getenv("emailpass");
            connectResult = connector.connect("harald.glab-plhak@t-online.de", password);
            ESender sender = new ESender(connectResult.getFirst(), connectResult.getSecond(),
                    T_ONLINE_SMTP_URI_HOST,
                    Integer.toString(T_ONLINE_SMTP_PORT));
            sender.sendEmail("harald.glab-plhak@t-online.de", password);
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
