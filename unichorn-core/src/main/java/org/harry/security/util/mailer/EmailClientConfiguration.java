package org.harry.security.util.mailer;

import org.pmw.tinylog.Logger;
import security.harry.org.emailer._1.MailboxType;
import security.harry.org.emailer._1.Mailboxes;

import javax.xml.bind.*;
import java.io.*;
import java.util.Optional;

import static org.harry.security.CommonConst.APP_DIR_EMAILER;
import static org.harry.security.CommonConst.PROP_MAILBOXES;

public class EmailClientConfiguration {

    private static Mailboxes providers = null;

    private static Mailboxes mailboxes = null;

    static {
        loadProviders();
        loadConfig();
    }

    public static Mailboxes loadProviders() {
        try {
            InputStream stream = EmailClientConfiguration.class.getResourceAsStream("/emailer/providerStore.xml");
            providers = loadXML(stream);
            return providers;
        } catch (Exception ex) {
            throw new IllegalStateException("email providers cannot be loaded ", ex);
        }
    }

    public static Mailboxes loadXML(InputStream stream) {
        try {
            JAXBContext jaxbContext =JAXBContext.newInstance(Mailboxes.class);
            Unmarshaller umarshall = jaxbContext.createUnmarshaller();
            Logger.trace("About to unmarshall unmarshaller created.....");
            Mailboxes root = (Mailboxes) umarshall.unmarshal(stream);
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

    public static void storeXML(OutputStream out) {
        JAXBContext jaxbContext;
        try
        {
            jaxbContext = JAXBContext.newInstance(Mailboxes.class);
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
                    mailboxes = new Mailboxes();
                }
            }
            Optional<MailboxType> providerData = providers.getMailbox()
                    .stream()
                    .filter(e -> e.getConfigName().equals(provider))
                    .findFirst();
            if (providerData.isPresent()) {
                MailboxType type = new MailboxType();
                type.setConfigName(email);
                type.setEmailAddress(email);
                type.setPassword("");
                type.setImapHost(providerData.get().getImapHost());
                type.setSmtpHost(providerData.get().getSmtpHost());
                type.setImapPort(providerData.get().getImapPort());
                type.setSmtpPort(providerData.get().getSmtpPort());
                mailboxes.getMailbox().add(type);
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
                    mailboxes = new Mailboxes();
                }
            }
        } catch (Exception ex) {
            throw new IllegalStateException("email mailbox config not loaded  ", ex);
        }
    }

    public static Mailboxes getProviders() {
        return providers;
    }

    public static Mailboxes getMailboxes() {
        return mailboxes;
    }
}
