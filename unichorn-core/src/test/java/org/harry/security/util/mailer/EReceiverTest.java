package org.harry.security.util.mailer;

import org.apache.commons.io.IOUtils;
import org.harry.security.testutils.TestBase;
import org.harry.security.util.Tuple;
import org.harry.security.util.pwdmanager.PasswordManager;
import org.junit.Test;
import org.pmw.tinylog.Logger;
import security.harry.org.emailer._1.AccountConfig;
import security.harry.org.emailer._1.ImapConfigType;

import javax.mail.Folder;
import javax.mail.Message;
import javax.mail.Store;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;

import static org.harry.security.util.mailer.EMailConnector.T_ONLINE_IMAP_PORT;
import static org.harry.security.util.mailer.EMailConnector.T_ONLINE_IMAP_URI_HOST;
import static org.junit.Assert.fail;

public class EReceiverTest extends TestBase {

    @Test
    public void getEMeilReadable() throws Exception {
        Tuple<Store, Folder> connectResult = null;
        try {
            ESender.setMailCapabilities();
            AccountConfig config = EmailClientConfiguration.getProviders();
            ImapConfigType type = config.getImapConfig()
                    .stream().filter(e -> e.getConfigName().equals("gmx"))
                    .findFirst()
                    .get();
            URL htmlURL = EMailConnectorTest.class.getResource("/data/mail.html");
            File htmlFile = new File(htmlURL.toURI());
            EMailConnector connector = new EMailConnector(type.getImapHost(), Integer.parseInt(type.getImapPort()));
            PasswordManager manager = new PasswordManager(System.getenv("credomail"));
            Tuple<String, String> passwordTuple = manager.readPassword("unichorn-teacher@gmx.de");
            String password = passwordTuple.getSecond();
            connectResult = connector.connect("unichorn-teacher@gmx.de", password);
            EReceiver receiver = new EReceiver(connectResult);
            Message[] messages = receiver.receiveMails();
            for (Message msg : messages) {
                System.out.println("From: " + msg.getFrom()[0].toString() + " Subject: " + msg.getSubject());
            }
            EReceiver.ReadableMail mail = receiver.openMail("INBOX", messages, (messages.length - 2));
            mail.getFromList().forEach(e -> Logger.trace(e));
            mail.getPartList().forEach(e -> {
                Logger.trace(e.getFirst());
                try {
                    Logger.trace(IOUtils.toString(e.getSecond().getInputStream(), Charset.defaultCharset().name()));
                } catch (IOException ioException) {
                   fail("cannot print content");
                }
            });
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
