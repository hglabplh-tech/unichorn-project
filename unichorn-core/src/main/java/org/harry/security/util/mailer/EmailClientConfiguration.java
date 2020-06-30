package org.harry.security.util.mailer;

import org.pmw.tinylog.Logger;
import security.harry.org.emailer._1.ImapConfigType;
import security.harry.org.emailer._1.SmtpConfigType;
import security.harry.org.emailer._1.AccountConfig;
import security.harry.org.emailer_client._1.ClientConfig;

import javax.xml.bind.*;
import java.io.*;
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

    public static void storeClientConf() {
        try {
            File mailboxFile = new File(APP_DIR_EMAILER, PROP_CLIENTCONF);
            OutputStream stream = new FileOutputStream(mailboxFile);
            storeXMLClientConf(stream);
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

    public static void storeXMLClientConf(OutputStream out) {
        JAXBContext jaxbContext;
        try
        {
            jaxbContext = JAXBContext.newInstance(ClientConfig.class);
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
            File clientConfFile = new File(APP_DIR_EMAILER, PROP_CLIENTCONF);
            if (clientConfig == null) {
                if (clientConfFile.exists()) {
                    clientConfig = loadXMLClientConf(new FileInputStream(clientConfFile));
                } else {
                    clientConfig = new ClientConfig();
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
