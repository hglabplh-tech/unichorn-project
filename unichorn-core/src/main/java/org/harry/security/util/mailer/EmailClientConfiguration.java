package org.harry.security.util.mailer;

import iaik.x509.X509Certificate;
import org.harry.security.util.SigningUtil;
import org.harry.security.util.Tuple;
import org.harry.security.util.algoritms.CryptoAlg;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.pmw.tinylog.Logger;
import security.harry.org.emailer._1.ImapConfigType;
import security.harry.org.emailer._1.SmtpConfigType;
import security.harry.org.emailer._1.AccountConfig;
import security.harry.org.emailer_client._1.ClientConfig;

import javax.activation.DataSource;
import javax.xml.bind.*;
import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Optional;

import static org.harry.security.CommonConst.*;

public class EmailClientConfiguration {

    private static AccountConfig providers = null;

    private static AccountConfig mailboxes = null;

    private static ClientConfig clientConfig = null;

    static {
        loadProviders();
        loadConfig();
    }

    public static AccountConfig loadProviders() {
        try {
            InputStream stream = EmailClientConfiguration.class.getResourceAsStream("/emailer/providerStore.xml");
            providers = loadXML(stream);
            return providers;
        } catch (Exception ex) {
            throw new IllegalStateException("email providers cannot be loaded ", ex);
        }
    }

    public static AccountConfig loadXML(InputStream stream) {
        try {
            JAXBContext jaxbContext =JAXBContext.newInstance(AccountConfig.class);
            Unmarshaller umarshall = jaxbContext.createUnmarshaller();
            Logger.trace("About to unmarshall unmarshaller created.....");
            AccountConfig root = (AccountConfig) umarshall.unmarshal(stream);
            return root;
        } catch (Exception ex) {
            throw new IllegalStateException("email providers cannot be loaded ", ex);
        }
    }

    public static ClientConfig loadClientConf(String password) {
        try {
            File inFile = new File(APP_DIR_EMAILER, PROP_CLIENTCONF);
            if (inFile.exists()) {
                KeyStore store = KeyStoreTool.loadAppStore();
                Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
                SigningBean bean = new SigningBean()
                        .setKeyStoreBean(new CertWriterReader.KeyStoreBean(keys.getSecond(), keys.getFirst()))
                        .setDataIN(new FileInputStream(inFile))
                        .setDecryptPWD(password)
                        .setOutputPath(inFile.getAbsolutePath());
                SigningUtil util = new SigningUtil();
                DataSource ds = util.decryptCMS(bean);
                ClientConfig root = loadXMLClientConf(ds.getInputStream());
                return root;
            } else {
                ClientConfig root = new ClientConfig();
                return root;
            }
        } catch (Exception ex) {
            throw new IllegalStateException("email providers cannot be loaded ", ex);
        }
    }

    public static ClientConfig loadXMLClientConf(InputStream stream) {
        try {
            JAXBContext jaxbContext =JAXBContext.newInstance(ClientConfig.class);
            Unmarshaller umarshall = jaxbContext.createUnmarshaller();
            Logger.trace("About to unmarshall unmarshaller created.....");
            ClientConfig root = (ClientConfig) umarshall.unmarshal(stream);
            return root;
        } catch (Exception ex) {
            throw new IllegalStateException("email providers cannot be loaded ", ex);
        }
    }

    public static void storeMailboxes() {
        try {
            File mailboxFile = new File(APP_DIR_EMAILER, PROP_MAILBOXES);
            OutputStream stream = new FileOutputStream(mailboxFile);
            storeXML(stream);
        } catch (Exception ex) {
            throw new IllegalStateException("email providers cannot be loaded ", ex);
        }
    }

    public static void newConfigItem(String email, String password, String provider, boolean isDefault) {
        newMailbox(email, password, provider);
        newSmtp(email, password, provider, isDefault);
    }

    public static void storeXML(OutputStream out) {
        JAXBContext jaxbContext;
        try
        {
            jaxbContext = JAXBContext.newInstance(AccountConfig.class);
            Marshaller marshal  = jaxbContext.createMarshaller();
            marshal.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marshal.marshal(mailboxes, out);
            return;
        }
        catch (JAXBException ex)
        {
            throw new IllegalStateException("mailboxes NOT stored -> error: " + ex.getMessage(), ex);
        }
    }

    public static void storeClientConf(ClientConfig config, String password) {
        try {
            File outFile = new File(APP_DIR_EMAILER, PROP_CLIENTCONF);
            OutputStream out = new FileOutputStream(outFile);
            DataSource dsInput = EmailClientConfiguration.storeXMLClientConf(config);
            KeyStore store = KeyStoreTool.loadAppStore();
            Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
            SigningBean bean = new SigningBean()
                    .setKeyStoreBean(new CertWriterReader.KeyStoreBean(keys.getSecond(), keys.getFirst()))
                    .setDataIN(dsInput.getInputStream())
                    .setDecryptPWD(password)
                    .setCryptoAlgorithm(CryptoAlg.PBE_SHAA3_KEY_TRIPLE_DES_CBC)
                    .setOutputPath(outFile.getAbsolutePath());
            SigningUtil util = new SigningUtil();
            DataSource ds = util.encryptCMS(bean);
            util.writeToFile(ds, bean);
        } catch (Exception ex) {
            Logger.trace("store client config failed with: " + ex.getMessage());
            Logger.trace(ex);
            throw new IllegalStateException("store client config failed with: ", ex);
        }
    }


    public static DataSource storeXMLClientConf(ClientConfig config) {
        JAXBContext jaxbContext;
        try
        {
            jaxbContext = JAXBContext.newInstance(ClientConfig.class);
            Marshaller marshal  = jaxbContext.createMarshaller();
            marshal.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            marshal.marshal(config, out);
            out.flush();
            ByteArrayInputStream stream = new ByteArrayInputStream(out.toByteArray());
            out.close();
            return new SigningUtil.InputStreamDataSource(stream);
        }
        catch (Exception ex)
        {
            throw new IllegalStateException("mailboxes NOT stored -> error: " + ex.getMessage(), ex);
        }
    }

    public static void newMailbox(String email, String password, String provider) {
        try {
            File mailboxFile = new File(APP_DIR_EMAILER, PROP_MAILBOXES);
            if (mailboxes == null) {
                if (mailboxFile.exists()) {
                    mailboxes = loadXML(new FileInputStream(mailboxFile));
                } else {
                    mailboxes = new AccountConfig();
                }
            }
            Optional<ImapConfigType> providerData = providers.getImapConfig()
                    .stream()
                    .filter(e -> e.getConfigName().equals(provider))
                    .findFirst();
            if (providerData.isPresent()) {
                ImapConfigType type = new ImapConfigType();
                type.setConfigName(email);
                type.setEmailAddress(email);
                type.setPassword("");
                type.setImapHost(providerData.get().getImapHost());
                type.setImapPort(providerData.get().getImapPort());
                mailboxes.getImapConfig().add(type);
            }
        } catch (Exception ex) {
            throw new IllegalStateException("email mailbox entry cannot be stored ", ex);
        }
    }

    public static void newSmtp(String email, String password, String provider, boolean isDefault) {
        try {
            File mailboxFile = new File(APP_DIR_EMAILER, PROP_MAILBOXES);
            if (mailboxes == null) {
                if (mailboxFile.exists()) {
                    mailboxes = loadXML(new FileInputStream(mailboxFile));
                } else {
                    mailboxes = new AccountConfig();
                }
            }
            Optional<SmtpConfigType> providerData = providers.getSmtpConfig()
                    .stream()
                    .filter(e -> e.getConfigName().equals(provider))
                    .findFirst();
            if (providerData.isPresent()) {
                SmtpConfigType type = new SmtpConfigType();
                type.setConfigName(email);
                type.setEmailAddress(email);
                type.setPassword("");
                type.setDefault(isDefault);
                type.setSmtpHost(providerData.get().getSmtpHost());
                type.setSmtpPort(providerData.get().getSmtpPort());
                mailboxes.getSmtpConfig().add(type);
            }
        } catch (Exception ex) {
            throw new IllegalStateException("email mailbox entry cannot be stored ", ex);
        }
    }

    public static void loadConfig() {
        try {
            File mailboxFile = new File(APP_DIR_EMAILER, PROP_MAILBOXES);
            if (mailboxes == null) {
                if (mailboxFile.exists()) {
                    mailboxes = loadXML(new FileInputStream(mailboxFile));
                } else {
                    mailboxes = new AccountConfig();
                }
            }
        } catch (Exception ex) {
            throw new IllegalStateException("email mailbox config not loaded  ", ex);
        }
    }

    public static AccountConfig getProviders() {
        return providers;
    }

    public static AccountConfig getMailboxes() {
        return mailboxes;
    }

    public static ClientConfig getClientConfig() {
        return clientConfig;
    }
}
