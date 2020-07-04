package org.harry.security.util.mailer;

import iaik.x509.X509Certificate;
import org.harry.security.testutils.TestBase;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.pwdmanager.PasswordManager;
import org.junit.Before;
import org.junit.Test;
import security.harry.org.emailer._1.ImapConfigType;
import security.harry.org.emailer._1.SmtpConfigType;
import security.harry.org.emailer._1.AccountConfig;

import javax.mail.Folder;
import javax.mail.Store;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.CoreMatchers.is;

public class ESenderTest extends TestBase {

    private static final String T_ONLINE_ADDRESS = "harald.glab-plhak@t-online.de";
    private static final String GMX_ADDRESS = "unichorn-teacher@gmx.de";
    private static final String GMAIL_ADDRESS = "unichorn.teacher@gmail.com";

    @Before
    public void initTest() {

    }
    @Test
    public void plainFromGMXToTOnline() throws Exception {
            Tuple<Store, Folder> connRes = null;
            try {
                KeyStore store = KeyStoreTool.loadAppStore();
                Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
            AccountConfig mailboxes = EmailClientConfiguration.getMailboxes();
            String email = GMX_ADDRESS;
            ImapConfigType box = getMailboxParameters(mailboxes, email);
            Tuple<String, String> credentials = getCredentials(email);
            connRes = connectIMAP(box, email, credentials);
            SmtpConfigType smtpBox = getSmtpParams(mailboxes, T_ONLINE_ADDRESS);
            Tuple<String, String> smtpProps = getCredentials(T_ONLINE_ADDRESS);
            ESender sender = ESender.newBuilder(connRes.getFirst(),
                    connRes.getSecond(),
                    smtpBox.getSmtpHost(),
                    smtpBox.getSmtpPort(), keys)
                    .setText("Test mail from: " + T_ONLINE_ADDRESS)
                    .setSubject("Test mail from JUNIT")
                    .setFrom(GMX_ADDRESS)
                    .addTo(T_ONLINE_ADDRESS)
                    .build();
                /*ESender sender = ESender.newBuilder(connRes.getFirst(),
                        connRes.getSecond(),
                        box.getSmtpHost(),
                        box.getSmtpPort())
                        .setText("Test mail from: " + T_ONLINE_ADDRESS)
                        .setSubject("Test mail from JUNIT")
                        .setFrom(GMX_ADDRESS)
                        .addTo(T_ONLINE_ADDRESS)
                        .build(); */
                boolean success = sender.sendEmail(smtpProps.getFirst(), smtpProps.getSecond());

        assertThat(success, is(true));
        } catch(Exception ex) {

        } finally {
            if (connRes != null) {
                if (connRes.getFirst() != null) {
                    Store store = connRes.getFirst();
                    store.close();
                }
            }
        }
    }

    @Test
    public void plainFromGMAILToTOnline() {

    }

    @Test
    public void plainFromTOnlineToGMX() {

    }

    @Test
    public void plainFromTOnlineToGMAIL() {

    }

    private ImapConfigType getMailboxParameters(AccountConfig mailboxes, String from) {
        Optional<ImapConfigType> mType = findFromParams(mailboxes, from);
        assertThat(mType.isPresent(), is(true));
        return mType.get();
    }

    private SmtpConfigType getSmtpParams(AccountConfig mailboxes, String from) {
        Optional<SmtpConfigType> mType = mailboxes.getSmtpConfig()
                .stream()
                .filter(e -> e.isDefault()).findFirst();
        assertThat(mType.isPresent(), is(true));
        return mType.get();
    }

    private Tuple<Store, Folder> connectIMAP(ImapConfigType box, String email, Tuple<String, String> credentials) {
        EMailConnector connector = new EMailConnector(box.getImapHost(),
                Integer.parseInt(box.getImapPort()));
        return connector.connect(email, credentials.getSecond());
    }

    private Tuple<String, String> getCredentials(String email) {
        String password = System.getenv("credomail");
        PasswordManager manager = new PasswordManager(password);
        return manager.readPassword(email);
    }


    private Optional<ImapConfigType> findFromParams(AccountConfig boxes, String email) {
        return boxes.getImapConfig().stream().filter(e -> email.equals(e.getEmailAddress())).findFirst();
    }
}
