package org.harry.security.util.mailer;

import org.apache.commons.mail.Email;
import org.apache.commons.mail.HtmlEmail;
import org.apache.commons.net.PrintCommandListener;
import org.apache.commons.net.imap.IMAPSClient;
import org.apache.commons.net.io.Util;
import org.apache.commons.net.smtp.SMTPClient;
import org.apache.commons.net.smtp.SMTPReply;
import org.apache.commons.net.smtp.SMTPSClient;
import org.apache.commons.net.smtp.SimpleSMTPHeader;

import javax.mail.Session;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

import static org.harry.security.util.httpclient.SSLUtils.createStandardContext;
import static org.harry.security.util.httpclient.SSLUtils.trustReallyAllShit;
import static org.harry.security.util.mailer.IMAPUtils.getEmailTrustAll;

public class ESender {

    private final String smtpHost;
    private final int smtpPort;

    public ESender(String smtpHost, int smtpPort) {

        this.smtpHost = smtpHost;
        this.smtpPort = smtpPort;
    }

    public boolean sendEmail (String username, String password) throws Exception {
        SSLContext.setDefault(trustReallyAllShit());
        Email mail = new HtmlEmail().addTo("heike.glab@t-online.de")
                .setSSLOnConnect(true)
                .setSubject("Ich liebe dich über alles")
                .setMsg("Hallo liebe Sophie, Ich liebe dich über alles")
                .setFrom("harald.glab-plhak@t-online.de");
        mail.setAuthentication(username, password);
        mail.setSslSmtpPort(Integer.toString(smtpPort));
        mail.setSmtpPort(smtpPort);
        mail.setHostName(smtpHost);
        String result = mail.send();
        return true;
    }

    public  void sendViaSmtp(String sender, String recipient, String subject)
    {
        String filename, server, cc;
        List<String> ccList = new ArrayList<String>();
        BufferedReader stdin;
        FileReader fileReader = null;
        Writer writer;
        SimpleSMTPHeader header;
        SMTPSClient client;

        stdin = new BufferedReader(new InputStreamReader(System.in));

        try {
            header = new SimpleSMTPHeader(sender, recipient, subject);
            client = new SMTPSClient();
            TrustManager manager = getEmailTrustAll();
            client.setTrustManager(manager);
            client.addProtocolCommandListener(new PrintCommandListener(
                    new PrintWriter(System.out), true));

            client.connect(smtpHost, smtpPort);

            if (!SMTPReply.isPositiveCompletion(client.getReplyCode()))
            {
                client.disconnect();
                System.err.println("SMTP server refused connection.");
                return;
            }
            client.login();

            client.setSender(sender);
            client.addRecipient(recipient);



            for (String recpt : ccList) {
                client.addRecipient(recpt);
            }

            writer = client.sendMessageData();

            if (writer != null)
            {
                writer.write(header.toString());
                writer.write("Hallo liebe Sophie, Ich liebe dich über alles");
                writer.close();
                client.completePendingCommand();
            }

            if (fileReader != null ) {
                fileReader.close();
            }

            client.logout();

            client.disconnect();
        }
        catch (IOException e)
        {
            e.printStackTrace();
            return;
        }
    }
}
