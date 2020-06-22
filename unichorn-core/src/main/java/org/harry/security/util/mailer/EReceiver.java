package org.harry.security.util.mailer;

import org.apache.commons.net.imap.IMAPSClient;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;

public class EReceiver {

    private final IMAPSClient imapClient;

    public EReceiver(IMAPSClient imapClient) {
        this.imapClient = imapClient;
    }

    public String receiveMails() {
        try {
            this.imapClient.capability();
            this.imapClient.select("inbox");
            this.imapClient.setReceiveBufferSize(4096);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            IMAPExportMbox.MboxListener chunkListener = new IMAPExportMbox.MboxListener(new BufferedWriter(new PrintWriter(out)),
                    "\n",true, true, false);
            this.imapClient.setChunkListener(chunkListener);
            this.imapClient.fetch("1:*", "body[header]");
            chunkListener.close();
            System.out.println(chunkListener.getItems().size());
            this.imapClient.getReplyStrings();
            return new String(out.toByteArray());
        } catch (Exception ex) {
            throw new IllegalStateException("fetch emails failed", ex);
        }
    }

    public String openMail(String folderName, int index) {
        try {
            this.imapClient.capability();
            this.imapClient.select("inbox");
            this.imapClient.setReceiveBufferSize(4096);
            String pattern = String.format("%d:%d", index, 1);
            this.imapClient.setChunkListener(null);
            this.imapClient.fetch(pattern, "RFC822");
            return this.imapClient.getReplyString();
        } catch (Exception ex) {
            throw new IllegalStateException("fetch emails failed", ex);
        }
    }
}
