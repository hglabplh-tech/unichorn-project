package org.harry.security.util.mailer;

import iaik.x509.X509Certificate;
import org.apache.commons.io.IOUtils;
import org.harry.security.testutils.TestBase;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.pwdmanager.PasswordManager;
import org.junit.Test;
import org.pmw.tinylog.Logger;
import security.harry.org.emailer._1.AccountConfig;
import security.harry.org.emailer._1.ImapConfigType;
import security.harry.org.emailer_client._1.CryptoConfigType;

import javax.mail.Folder;
import javax.mail.Message;
import javax.mail.Store;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.PrivateKey;

import static org.junit.Assert.fail;

public class EReceiverTest extends TestBase {

    @Test
    public void getEMeilReadable() throws Exception {
        Tuple<Store, Folder> connectResult = null;
        try {
            KeyStore store = KeyStoreTool.loadAppStore();
            Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
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
            EReceiver receiver = new EReceiver(connectResult, getPrivateKeyTuple());
            Message[] messages = new Message[0];
            messages = receiver.receiveMails(null);
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

    public static Tuple<PrivateKey, X509Certificate[]> getPrivateKeyTuple() throws FileNotFoundException {
        CryptoConfigType cryptoConf = EmailClientConfiguration
                .getClientConfig()
                .getCryptoConfig()
                .get(0);
        if (cryptoConf.getKeyStoreFile().equals("::SMARTCARD::")) {
            return null;
        } else {
            File keyStoreFile = new File(cryptoConf.getKeyStoreFile());
            KeyStore keystore = KeyStoreTool.loadStore(
                    new FileInputStream(keyStoreFile),
                    cryptoConf.getPassword().toCharArray(), "PKCS12");
            return KeyStoreTool.getKeyEntry(keystore,
                    cryptoConf.getAlias(), cryptoConf.getPassword().toCharArray());
        }
    }
}
