package org.harry.security.util.mailer;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.SignerInfo;
import iaik.smime.*;
import iaik.x509.X509Certificate;
import org.apache.commons.io.IOUtils;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.httpclient.SSLUtils;
import org.pmw.tinylog.Logger;

import javax.activation.CommandMap;
import javax.activation.DataHandler;
import javax.activation.FileDataSource;
import javax.activation.MailcapCommandMap;
import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.net.ssl.SSLContext;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;

/**
 * This class is responsible for sending e-mails either unsigned or signed
 * @author Harald Glab-Plhak
 */
public class ESender {

    private final Store store;
    private final String  smtpPort;
    private final String host;
    private final Folder defaultFolder;

    private String from;
    private List<String> receipients = new ArrayList<>();
    private String subject;
    private String text;
    private List<File> attachments =  new ArrayList<>();


    /**
     * The CTOr of the class
     * @param store the imap store
     * @param folder the imap default folder
     * @param host the smtp host
     * @param smtpPort the smtp port
     */
    public ESender(Store store, Folder folder, String host, String smtpPort) {
        this.host = host;
        this.smtpPort = smtpPort;
        this.store = store;
        this.defaultFolder = folder;
        setMailCapabilities();
    }

    /**
     * Send a simple e-mail
     * @param username the smtp user
     * @param password the users password
     * @return true if success
     */
    public boolean sendEmail (String username, String password)  {
        try {
            TrustStrategy strategie = new TrustAllStrategy();
            SSLContext context =
                    SSLContextBuilder.create().loadTrustMaterial(strategie).build();
            SSLContext.setDefault(context);
            Properties props = System.getProperties();

            props.put("mail.smtp.host", host);
            props.put("mail.smtp.port", smtpPort);
            // SSL Factory
            props.put("mail.smtp.socketFactory.class",
                    "javax.net.ssl.SSLSocketFactory");

            Session session = Session.getInstance(props, new javax.mail.Authenticator() {

                // override the getPasswordAuthentication
                // method
                protected PasswordAuthentication
                getPasswordAuthentication() {
                    return new PasswordAuthentication(username,
                            password);
                }
            });
            Transport transport = session.getTransport();
            transport.connect(username, password);
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress(from));

            if (receipients.size() == 0) {
                Logger.trace("no receipients defined cannot send mail");
                throw new IllegalStateException("no receipients defined cannot send mail");
            }
            for (String to: receipients) {
                message.addRecipient(Message.RecipientType.TO,
                        new InternetAddress(to));
            }
            message.setSubject(subject);
            if (attachments.size() > 0) {
                MimeMultipart multi = new MimeMultipart();
                for (File attachement:attachments) {
                    MimeBodyPart part = new MimeBodyPart();
                    part.setContentID(UUID.randomUUID().toString());
                    part.attachFile(attachement);
                }
                message.setContent(multi);
            }
            message.setText(text);
            transport.sendMessage(message, message.getAllRecipients());
            Folder sentFolder = store.getFolder("INBOX.Sent");
            Folder[] folderList = this.defaultFolder.list();
            sentFolder.open(Folder.READ_WRITE);
            Message[] temp = new Message[1];
            temp[0] = message;
            sentFolder.appendMessages(temp);
            sentFolder.close(false);
            return true;
        } catch(Exception ex) {
            Logger.trace("error occurred during send mail " + ex.getMessage());
            Logger.trace(ex);
            return false;
        }
    }

    /**
     * Send a e-mail with signed content
     * @param username the smtp user name
     * @param password the users password
     * @return true if success     *
     */
    public boolean sendSigned(String username, String password)
    {

        try {
            Session session = createSession(username, password);

            KeyStore keystore = KeyStoreTool.loadAppStore();
            Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(keystore);
            // Create a demo Multipart
            SignedContent sc = createMultiPartContent(keys);
            MimeMessage message = createMessageAndSetReceipients(session);

            message.setContent(sc, sc.getContentType());
            sc.setHeaders(message);

            message.setSubject(subject);
            //transport.sendMessage(message, message.getAllRecipients());
            Transport.send(message, message.getAllRecipients(), username, password);
            Folder sentFolder = store.getFolder("INBOX.Sent");
            Folder[] folderList = this.defaultFolder.list();
            sentFolder.open(Folder.READ_WRITE);
            Message[] tempmsg = new Message[1];
            tempmsg[0] = message;
            sentFolder.appendMessages(tempmsg);
            sentFolder.close(false);
            return true;
        } catch(Exception ex) {
            Logger.trace("send signed failed with: " + ex.getMessage());
            Logger.trace(ex);
            throw new IllegalStateException("send signed failed with: " + ex.getMessage(), ex);
        }
    }

    public boolean sendSignedAndEncrypted(String username, String password) {
        try {
            Session session = createSession(username, password);

            KeyStore keystore = KeyStoreTool.loadAppStore();
            Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(keystore);
            // Create a demo Multipart
            SignedContent sc = createMultiPartContent(keys);

            Message message = createSignedAndEncryptedContent(session, keys);
            message.setContent(sc, sc.getContentType());
            sc.setHeaders(message);

            message.setSubject(subject);
            //transport.sendMessage(message, message.getAllRecipients());
            Transport.send(message, message.getAllRecipients(), username, password);
            Folder sentFolder = store.getFolder("INBOX.Sent");
            Folder[] folderList = this.defaultFolder.list();
            sentFolder.open(Folder.READ_WRITE);
            Message[] tempmsg = new Message[1];
            tempmsg[0] = message;
            sentFolder.appendMessages(tempmsg);
            sentFolder.close(false);
            return true;
        } catch (Exception ex) {
            throw new IllegalStateException("error signing and encrypting", ex);
        }
    }



    /**
     * Crreating a signed multipart-content
     * @param keys the private key and the certificate chain
     * @return the SignedContent object
     * @throws MessagingException error case
     */
    private SignedContent createMultiPartContent(Tuple<PrivateKey, X509Certificate[]> keys) throws MessagingException {
        MimeBodyPart mbp1 = new SMimeBodyPart();
        mbp1.setText(text);
        DataHandler multipart = null;
        // try to test an attachment
        if (attachments.size() == 1) {
            MimeBodyPart attachment = new SMimeBodyPart();
            attachment.setDataHandler(new DataHandler(new FileDataSource(attachments.get(0))));
            attachment.setFileName("anonymous");
            Multipart mp = new SMimeMultipart();
            mp.addBodyPart(mbp1);
            mp.addBodyPart(attachment);
            multipart = new DataHandler(mp, mp.getContentType());
        }


        return createSignedContent(keys, multipart);
    }

    /**
     * creates the connected transport object
     * @param username the smtp user name
     * @param password the users password
     * @param session the session
     * @return the transport object
     * @throws MessagingException error case
     */
    private Transport connectGetTransport(String username, String password, Session session) throws MessagingException {
        Transport transport = session.getTransport();
        transport.connect(username, password);
        return transport;
    }

    /**
     * Create a initialized session for smtp
     * @param username the smtp user name
     * @param password the users password
     * @return the initialized session object
     * @throws Exception error case
     */
    private Session createSession(String username, String password) throws Exception {
        SSLContext context =
                SSLUtils.createStandardContext();
        SSLContext.setDefault(context);
        Properties props = System.getProperties();

        props.put("mail.smtp.host", host);
        props.put("mail.smtp.port", smtpPort);
        // SSL Factory
        props.put("mail.smtp.socketFactory.class",
                "javax.net.ssl.SSLSocketFactory");




        return Session.getInstance(props, new Authenticator() {

            // override the getPasswordAuthentication
            // method
            protected PasswordAuthentication
            getPasswordAuthentication() {
                return new PasswordAuthentication(username,
                        password);
            }
        });
    }

    /**
     * Set the e-mail capabilities to send signed mailes
     */
    private void setMailCapabilities() {
        MailcapCommandMap mc = (MailcapCommandMap) CommandMap.getDefaultCommandMap();
        mc.addMailcap("text/html;; x-java-content-handler=com.sun.mail.handlers.text_html");
        mc.addMailcap("text/xml;; x-java-content-handler=com.sun.mail.handlers.text_xml");
        mc.addMailcap("text/plain;; x-java-content-handler=com.sun.mail.handlers.text_plain");
        mc.addMailcap("multipart/*;; x-java-content-handler=com.sun.mail.handlers.multipart_mixed");
        mc.addMailcap("message/rfc822;; x-java-content- handler=com.sun.mail.handlers.message_rfc822");
        mc.addMailcap("multipart/signed;; x-java-content-handler=iaik.smime.signed_content");
        mc.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=iaik.smime.signed_content");
        mc.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=iaik.smime.encrypted_content");
        mc.addMailcap("application/pkcs7-signature;; x-java-content-handler=iaik.smime.signed_content");
        mc.addMailcap("application/pkcs7-mime;; x-java-content-handler=iaik.smime.encrypted_content");
        mc.addMailcap("application/x-pkcs10;; x-java-content-handler=iaik.smime.pkcs10_content");
        mc.addMailcap("application/pkcs10;; x-java-content-handler=iaik.smime.pkcs10_content");
        CommandMap.setDefaultCommandMap(mc);
    }

    private Message createSignedAndEncryptedContent(Session session, Tuple<PrivateKey,
            X509Certificate[]> keys) throws MessagingException {
        Message msg = this.createMessageAndSetReceipients(session);

        DataHandler dataHandler = null;
        // try to test an attachment
        if (attachments.size() == 1) {
            MimeBodyPart attachment = new SMimeBodyPart();
            attachment.setDataHandler(new DataHandler(new FileDataSource(attachments.get(0))));
            attachment.setFileName("anonymous");
            Multipart mp = new SMimeMultipart();
            mp.addBodyPart(attachment);
            dataHandler = new DataHandler(mp, mp.getContentType());
        }
        SignedContent sc = new SignedContent(true);
        if (dataHandler != null) {
            sc.setDataHandler(dataHandler);
        } else {
            sc.setText(text);
        }
        sc.setCertificates(keys.getSecond());
        try {
            sc.addSigner((RSAPrivateKey) keys.getFirst(), keys.getSecond()[0], keys.getSecond()[0], true);
        } catch (NoSuchAlgorithmException ex) {
            throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
        }
        EncryptedContent ec = new EncryptedContent(sc);
        // encrypt for the recipient
        ec.addRecipient(keys.getSecond()[0], (AlgorithmID) AlgorithmID.rsaEncryption.clone());
        // I want to be able to decrypt the message, too
        ec.addRecipient(keys.getSecond()[0], (AlgorithmID) AlgorithmID.rsaEncryption.clone());
        // set the encryption algorithm
        try {
            ec.setEncryptionAlgorithm((AlgorithmID) AlgorithmID.rc2_CBC.clone(), 128);
        } catch (NoSuchAlgorithmException ex) {
            throw new MessagingException("Content encryption algorithm not supported: " + ex.getMessage());
        }
        msg.setContent(ec, ec.getContentType());
        // let the EncryptedContent update some message headers
        ec.setHeaders(msg);

        return msg;
    }

        /**
         * create the Message object and set the receipients
         * @param session the active session
         * @return the MimeMessage object
         * @throws MessagingException error case
         */
        private MimeMessage createMessageAndSetReceipients(Session session) throws MessagingException {
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress(from));
            message.setSentDate(new Date());

            if (receipients.size() == 0) {
                Logger.trace("no receipients defined cannot send mail");
                throw new IllegalStateException("no receipients defined cannot send mail");
            }
            for (String to : receipients) {
                message.addRecipient(Message.RecipientType.TO,
                        new InternetAddress(to));
            }
            return message;
        }

        /**
         * create a single signed content
         * @param keys the keys
         * @param multipart the multipart data-handler
         * @return the signed content object
         * @throws MessagingException error case
         */
        private SignedContent createSignedContent (Tuple < PrivateKey, X509Certificate[]>keys, DataHandler multipart) throws
        MessagingException {
            SignedContent sc = new SignedContent(true);
            if (multipart != null) {
                sc.setDataHandler(multipart);
            } else {
                sc.setText(text);
            }
            sc.setCertificates(keys.getSecond());

            try {
                sc.addSigner((RSAPrivateKey) keys.getFirst(), keys.getSecond()[0], keys.getSecond()[0], true);
            } catch (NoSuchAlgorithmException ex) {
                throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
            }
            return sc;
        }

        /**
         * get a fresh builoder for this class
         * @param store the imap store
         * @param folder the default folder
         * @param host the smtp host
         * @param smtpPort the smtp port
         * @return a initialized ESender object
         */
        public static Builder newBuilder (Store store, Folder folder, String host, String smtpPort){
            return new Builder(store, folder, host, smtpPort);
        }

        /**
         * ÄThe Builder class itself
         */
        public static class Builder {

            /**
             * the instance to be created
             */
            private ESender sender = null;

            public Builder(Store store, Folder folder, String host, String smtpPort) {
                sender = new ESender(store, folder, host, smtpPort);
            }

            public Builder setFrom(String from) {
                sender.from = from;
                return this;
            }

            public Builder addTo(String to) {
                sender.receipients.add(to);
                return this;
            }

            public Builder setReceipients(List<String> receipients) {
                sender.receipients.addAll(receipients);
                return this;
            }

            public Builder addAttachement(File file) {
                sender.attachments.add(file);
                return this;
            }

            public Builder setAttachements(List<File> files) {
                sender.attachments.addAll(files);
                return this;
            }

            public Builder setSubject(String subject) {
                sender.subject = subject;
                return this;
            }

            public Builder setText(String text) {
                sender.text = text;
                return this;
            }

            public ESender build() {
                return this.sender;
            }
        }
    }
