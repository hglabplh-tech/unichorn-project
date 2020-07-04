package org.harry.security.util.mailer;

import com.sun.mail.imap.IMAPFolder;
import iaik.smime.EncryptedContent;
import iaik.smime.SMimeBodyPart;
import iaik.smime.SMimeMultipart;
import iaik.smime.SignedContent;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import org.harry.security.util.SigningUtil;
import org.harry.security.util.Tuple;
import org.pmw.tinylog.Logger;

import javax.activation.DataHandler;
import javax.mail.*;
import javax.mail.internet.MimeMultipart;
import java.io.*;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

public class EReceiver {

    private final Tuple<Store, Folder> instance;

    private final Tuple<PrivateKey, X509Certificate[]> keys;

    public EReceiver(Tuple<Store, Folder> instance, Tuple<PrivateKey, X509Certificate[]> keys) {
        this.instance = instance;
        this.keys = keys;
    }

    public Message[] receiveMails() {
        try {
            int totalNumberOfMessages = 0;
            IMAPFolder  folder = (IMAPFolder) instance.getSecond();
            folder.open(Folder.READ_ONLY);
            /*
             * Now we fetch the message from the IMAP folder in descending order.
             *
             * This way the new mails arrive with the first chunks and older mails
             * afterwards.
             */
            long largestUid = folder.getUIDNext() - 1;
            int chunkSize = 500;
            for (long offset = 0; offset < largestUid; offset += chunkSize) {
                long start = Math.max(1, largestUid - offset - chunkSize + 1);
                long end = Math.max(1, largestUid - offset);

                /*
                 * The next line fetches the existing messages within the
                 * given range from the server.
                 *
                 * The messages are not loaded entirely and contain hardly
                 * any information. The Message-instances are mostly empty.
                 */
                long beforeTime = System.nanoTime();
                Message[] messages = folder.getMessagesByUID(start, end);
                totalNumberOfMessages += messages.length;
                System.out.println("found " + messages.length + " messages (took " + (System.nanoTime() - beforeTime) / 1000 / 1000 + " ms)");

                /*
                 * If we would access e.g. the subject of a message right away
                 * it would be fetched from the IMAP server lazily.
                 *
                 * Fetching the subjects of all messages one by one would
                 * produce many requests to the IMAP server and take too
                 * much time.
                 *
                 * Instead with the following lines we load some information
                 * for all messages with one single request to save some
                 * time here.
                 */
                beforeTime = System.nanoTime();
                // this instance could be created outside the loop as well
                FetchProfile metadataProfile = new FetchProfile();
                // load flags, such as SEEN (read), ANSWERED, DELETED, ...
                metadataProfile.add(FetchProfile.Item.FLAGS);
                // also load From, To, Cc, Bcc, ReplyTo, Subject and Date
                metadataProfile.add(FetchProfile.Item.ENVELOPE);
                // load it all
                metadataProfile.add(IMAPFolder.FetchProfileItem.MESSAGE);
                // we could as well load the entire messages (headers and body, including all "attachments")
                // metadataProfile.add(IMAPFolder.FetchProfileItem.MESSAGE);
                folder.fetch(messages, metadataProfile);
                System.out.println("loaded messages (took " + (System.nanoTime() - beforeTime) / 1000 / 1000 + " ms)");
                folder.close(false);
                return messages;
            }
         return null;
        } catch (Exception ex) {
            throw new IllegalStateException("fetch emails failed", ex);
        }
    }

    public ReadableMail openMail(String folderName, Message[] messages,int index) {
        try {
            this.instance.getFirst().getFolder(folderName);
            IMAPFolder folder = (IMAPFolder) this.instance.getFirst().getFolder(folderName);
            folder.open(Folder.READ_ONLY);
            // this instance could be created outside the loop as well
            FetchProfile metadataProfile = new FetchProfile();
           // metadataProfile.add(IMAPFolder.FetchProfileItem.MESSAGE);
           // folder.fetch(messages, metadataProfile);
            folder.close(false);
            Message actualMessage = messages[index];
            ReadableMail mail = new ReadableMail(actualMessage, keys);
            mail.analyzeContent(null);
            return mail;
        } catch (Exception ex) {
            Logger.trace("fetch failed" + ex.getMessage());
            Logger.trace(ex);
            throw new IllegalStateException("fetch failed", ex);
        }
    }

    public static class ReadableMail{
        private final Message message;

        private final Tuple<PrivateKey, X509Certificate[]> keys;

        List<String> fromList = new ArrayList<>();

        List<String> toList = new ArrayList<>();

        X509Certificate signer = null;

        List<Tuple<String, DataHandler>> partList = new ArrayList<>();

        public ReadableMail(Message message, Tuple<PrivateKey, X509Certificate[]> keys) {
            this.keys = keys;
            this.message = message;
        }

        public void analyzeContent(Object contentObj) {
            try {
                String type = null;
                if (contentObj == null) {
                    Address[] addresses = message.getFrom();
                    if (addresses != null) {
                        for (Address address : addresses) {
                            fromList.add(address.toString());
                        }
                    }
                    addresses = message.getAllRecipients();
                    if (addresses != null) {
                        for (Address address : addresses) {
                            toList.add(address.toString());
                        }
                    }
                    contentObj = message.getContent();
                    type = message.getContentType();
                }
                if (contentObj instanceof EncryptedContent) {
                    EncryptedContent ec = (EncryptedContent)contentObj;
                    ec.decryptSymmetricKey(keys.getFirst(), 0);
                    analyzeContent(ec.getContent());
                } else if (contentObj instanceof SignedContent) {
                    SignedContent signedContent = (SignedContent)contentObj;
                    verifySigned(signedContent);
                    DataHandler handler = signedContent.getDataHandler();
                    signedContent.getContentType();
                    Object sCont= signedContent.getContent();
                    if (sCont instanceof Multipart) {
                        Logger.trace("found multipart");
                        MimeMultipart multipart = (MimeMultipart)sCont;
                        analyzeMultipartContent(multipart);
                    } else if (sCont instanceof InputStream) {

                    }
                }
                if (contentObj instanceof SMimeMultipart) {
                    String partType = null;
                    SMimeMultipart multi = (SMimeMultipart)contentObj;
                    int count = multi.getCount();
                    for (int ind = 0; ind < count; ind++) {
                        BodyPart sMimePart = multi.getBodyPart(ind);
                        if (sMimePart.getContent() instanceof Multipart) {
                            analyzeMultipartContent((Multipart) sMimePart.getContent());
                        } else {
                            Logger.trace("Part type of part: " + ind+ " is: " + partType);
                            DataHandler dataHandler = sMimePart.getDataHandler();
                            partType = sMimePart.getContentType();
                            partList.add(new Tuple<>(partType, dataHandler));
                        }

                    }

                }
                if (contentObj instanceof Multipart) {
                    Logger.trace("found multipart");
                    MimeMultipart multipart = (MimeMultipart)contentObj;
                    analyzeMultipartContent(multipart);
                }  else  if (contentObj instanceof String){
                    String content = (String)message.getContent();
                    ByteArrayInputStream stream = new ByteArrayInputStream(content.getBytes());
                    DataHandler dataHandler = new DataHandler(new SigningUtil.InputStreamDataSource(stream));
                    partList.add(new Tuple<>(type, dataHandler));
                } else if (contentObj instanceof InputStream) {
                    DataHandler dataHandler =
                            new DataHandler(new SigningUtil.InputStreamDataSource((InputStream)contentObj));
                    partList.add(new Tuple<>(type, dataHandler));
                }
            } catch (Exception ex) {
                Logger.trace("analyzeContent failed" +  ex.getMessage());
                Logger.trace(ex);
                throw new IllegalStateException("analyzeContent failed", ex);
            }
        }

        private void verifySigned(SignedContent signedContent) throws Exception {
            this.signer = signedContent.verify();
            Certificate[] certs = signedContent.getCertificates();
            X509Certificate [] iaikCerts = Util.convertCertificateChain(certs);
            signedContent.getDataHandler();
            for (int index = 0;index < signedContent.getCount(); index++) {
                BodyPart part = signedContent.getBodyPart(index);
                Object partObj = part.getContent();
                String partType = part.getContentType();
                if (partObj instanceof SMimeBodyPart) {
                    Logger.trace("Part type of part: " + index + " is: " + partType);
                    DataHandler dataHandler = part.getDataHandler();
                    partList.add(new Tuple<>(partType, dataHandler));
                }
                else if (partObj instanceof SMimeMultipart) {
                    SMimeMultipart multi = (SMimeMultipart)partObj;
                    int count = multi.getCount();
                    for (int ind = 0; ind < count; ind++) {
                        BodyPart sMimePart = multi.getBodyPart(ind);
                        if (sMimePart.getContent() instanceof Multipart) {
                            analyzeMultipartContent((Multipart) sMimePart.getContent());
                        } else {
                            Logger.trace("Part type of part: " + index + " is: " + partType);
                            DataHandler dataHandler = sMimePart.getDataHandler();
                            partType = sMimePart.getContentType();
                            partList.add(new Tuple<>(partType, dataHandler));
                        }

                    }

                } else {
                    Logger.trace("Part type of part: " + index + " is: " + partType);
                    DataHandler dataHandler = part.getDataHandler();
                    partList.add(new Tuple<>(partType, dataHandler));
                }

            }
        }

        private void analyzeMultipartContent(Multipart multipart) throws MessagingException, IOException {
            int countMembers = multipart.getCount();
            for (int index = 0; index < countMembers;index++) {
                BodyPart part = multipart.getBodyPart(index);
                String partType = part.getContentType();
                Object obj = part.getContent();
                if (obj instanceof Multipart) {
                    analyzeMultipartContent((Multipart)obj);
                    return;
                }
                Logger.trace("Part type of part: " + index + " is: " + partType);
                DataHandler dataHandler = part.getDataHandler();
                partList.add(new Tuple<>(partType, dataHandler));
            }

        }

        public Message getMessage() {
            return message;
        }

        public List<String> getFromList() {
            return fromList;
        }

        public List<Tuple<String, DataHandler>> getPartList() {
            return partList;
        }

        public List<String> getToList() {
            return toList;
        }

        public boolean isSigned() {
            return (this.signer != null);
        }

        public X509Certificate getSigner() {
            return signer;
        }
    }

}
