package org.harry.security.util.mailer;

import org.apache.bcel.generic.FADD;
import org.apache.commons.mail.Email;
import org.apache.commons.mail.HtmlEmail;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.pmw.tinylog.Logger;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.net.ssl.SSLContext;

import java.util.Properties;

import static org.harry.security.util.httpclient.SSLUtils.trustReallyAllShit;

public class ESender {

    private final Store store;
    private final String  smtpPort;
    private final String host;
    private final Folder defaultFolder;


    public ESender(Store store, Folder folder, String host, String smtpPort) {
        this.host = host;
        this.smtpPort = smtpPort;
        this.store = store;
        this.defaultFolder = folder;
    }

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
            message.setFrom(new InternetAddress("harald.glab-plhak@t-online.de"));
            message.addRecipient(Message.RecipientType.TO,
                    new InternetAddress("heike.glab@t-online.de"));
            message.setSubject("I love you so");
            message.setText("Hi Sophie, I love you from earth too moon and back. You are my sunshine. You are like " +
                    "a beautiful rose which blooms in the snow and ice of the winter and gives hope." +
                    "I will get old and grey with you :-)");
            Address[] adresses = new Address[1];
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
}
