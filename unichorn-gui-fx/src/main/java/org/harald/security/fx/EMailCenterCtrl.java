package org.harald.security.fx;

import com.sun.mail.imap.IMAPFolder;
import iaik.x509.X509Certificate;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.ObservableList;
import javafx.event.*;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebView;
import org.apache.commons.io.IOUtils;
import org.harry.security.util.AlgorithmPathChecker;
import org.harry.security.util.ConfigReader;
import org.harry.security.util.Tuple;
import org.harry.security.util.VerifyUtil;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.mailer.*;
import org.harry.security.util.pwdmanager.PasswordManager;
import org.pmw.tinylog.Logger;
import security.harry.org.emailer._1.AccountConfig;
import security.harry.org.emailer._1.ImapConfigType;


import javax.activation.DataHandler;
import javax.mail.*;
import javax.mail.internet.MimeMessage;

import java.io.*;
import java.nio.charset.Charset;
import java.util.*;

import static org.harald.security.fx.util.Miscellaneous.contexts;
import static org.harald.security.fx.util.Miscellaneous.getPrivateKeyTuple;
import static org.harry.security.CommonConst.APP_DIR_EMAILER;
import static org.harry.security.CommonConst.PROP_FOLDERINDEXFILE;

public class EMailCenterCtrl implements ControllerInit {

    @FXML
    TreeView<String> controlTree;

    @FXML
    TextField subject;

    @FXML
    ComboBox<String> fromBox;

    @FXML ComboBox<String> to;

    @FXML
    WebView webContentView;

    @FXML
    ListView<String> mailList;

    @FXML ComboBox<String> attachments;

    @FXML
    Button showSig;

    @FXML
    Label signedBy;

    List<Tuple<String, DataHandler>> contentList = new ArrayList<>();
    static Map<String, Tuple<Session, Tuple<Store, Folder>>> connectResult = new HashMap<>();

    Map<String, Folder[]> foldersMap = new HashMap<>();

    Map<String, Message> actualMessages = new LinkedHashMap<>();

    List<Message> actualMessagesList = new ArrayList<>();

    Map<String, Message> messageMap = new LinkedHashMap<>();

    Message displayedMessage = null;

    static AccountConfig mailboxes;

    public Scene init() {
        ESender.setMailCapabilities();
        mailList.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<String>() {
            @Override
            public void changed(ObservableValue<? extends String> observableValue, String s, String t1) {
                signedBy.setText("");
                attachments.getItems().clear();
                ObservableList<Integer> indices = mailList.getSelectionModel().getSelectedIndices();
                if (indices.size() > 0) {
                    try {
                        int index = indices.get(0);
                        displayedMessage = actualMessagesList.get(index);
                        EReceiver.ReadableMail mail = new EReceiver.ReadableMail(displayedMessage, getPrivateKeyTuple());
                        mail.analyzeContent(null);
                        if (mail.isSigned()) {
                            showSig.setDisable(false);
                        } else {
                            showSig.setDisable(true);
                        }
                        fromBox.getItems().clear();
                        fromBox.getItems().addAll(mail.getFromList());
                        fromBox.getSelectionModel().select(0);
                        to.getItems().clear();
                        to.getItems().addAll(mail.getToList());
                        to.getSelectionModel().select(0);
                        subject.setText(displayedMessage.getSubject());
                        WebEngine engine = webContentView.getEngine();
                        contentList = mail.getPartList();
                        if (contentList.size() > 0) {
                            InputStream stream = contentList.get(0).getSecond().getInputStream();
                            String content = IOUtils.toString(stream, Charset.defaultCharset());
                            engine.loadContent(content);
                        }
                        attachments.getItems().clear();
                        for (int attachmentIndex = 0; attachmentIndex < contentList.size(); attachmentIndex++) {
                            attachments.getItems().add(contentList.get(attachmentIndex).getFirst());
                            attachments.getSelectionModel().select(0);
                        }
                    } catch (Exception ex) {
                        Logger.trace("cannot fill out mail form: " + ex.getMessage());
                        Logger.trace(ex);
                        throw new IllegalStateException("cannot fill out mail form: " + ex.getMessage(), ex);
                    }

                }
            }
        });
        controlTree.getSelectionModel().selectedItemProperty()
                .addListener(new ChangeListener<TreeItem<String>>() {

                    @Override
                    public void changed(
                            ObservableValue<? extends TreeItem<String>> observable,
                            TreeItem<String> old_val, TreeItem<String> new_val) {
                        TreeItem<String> selectedItem = new_val;
                        String key = "blubber";
                        TreeItem<String> parent = selectedItem.getParent();
                        if (parent != null) {
                            key = parent.getValue();
                        }
                        Folder[] folders = foldersMap.get(key);
                        if (folders != null) {
                            Tuple<Session,Tuple<Store, Folder>> login = connectResult.get(key);
                            List<String> mailEntries = new ArrayList<>();
                            Optional<Folder> selected =
                                    Arrays.stream(folders)
                                            .filter(e -> e.getName().equals(new_val.getValue()))
                                    .findFirst();
                            if (selected.isPresent()) {
                                EReceiver receiver = null;
                                try {
                                    receiver = new EReceiver(new Tuple<Store, Folder>(login.getSecond().getFirst(),
                                            selected.get()), getPrivateKeyTuple());
                                } catch (FileNotFoundException e) {
                                    e.printStackTrace();
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                                String path = key + new_val.getValue();
                                Message[] messagesReceived = new Message[0];
                                try {
                                    messageMap = loadMessages(path, login);
                                    messagesReceived = receiver.receiveMails(path);
                                    saveMessages(messagesReceived, path);
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                                actualMessages.clear();
                                actualMessagesList.clear();
                                actualMessages.putAll(messageMap);
                                actualMessagesList.addAll(messageMap.values());
                                try {
                                    for (Map.Entry<String, Message> msgEntry: actualMessages.entrySet()) {
                                        MimeMessage msg = (MimeMessage) msgEntry.getValue();
                                        Flags flagEntries = msg.getFlags();
                                        Flags.Flag[] flags = flagEntries.getSystemFlags();
                                        boolean seen = Arrays.asList(flags).contains(Flags.Flag.SEEN);

                                        Address[] from = new Address[0];
                                        try {
                                            from = msg.getFrom();
                                        } catch(Exception ex) {
                                            Logger.trace("Ignorable From Address Error" + ex.getMessage());
                                        }
                                        StringBuffer buf = new StringBuffer();
                                        for (Address addr : from) {
                                            buf.append(addr.toString() + " , ");
                                        }
                                        if (!seen) {
                                            mailEntries.add("NEW -- " + msg.getSubject() + ";;" + buf.toString());
                                        } else {
                                            mailEntries.add(msg.getSubject() + ";;" + buf.toString());
                                        }
                                    }
                                    mailList.getItems().clear();
                                    mailList.getItems().addAll(mailEntries);
                                } catch (Exception ex) {
                                    Logger.trace(" cannot load entries: " + ex.getMessage());
                                    Logger.trace(ex);
                                    throw new IllegalStateException(" cannot load entries", ex);
                                }
                            }
                        }
                        System.out.println("Selected Text : " + selectedItem.getValue());
                        // do what ever you want
                    }

                });
        TreeItem<String> root = new TreeItem<>();
        root.setValue("MailBoxes");
        controlTree.setRoot(root);
        refreshTree();
        return controlTree.getScene();
    }

    @FXML
    public void writeMail(ActionEvent event) throws IOException {
        SecHarry.setRoot("sendmail", SecHarry.CSS.UNICHORN);
    }

    @FXML
    public void reply(ActionEvent event) throws Exception {
        if (displayedMessage != null) {
            contexts.get().getToAddresses().clear();
            contexts.get().getToAddresses()
                    .add(Arrays.asList(displayedMessage
                            .getFrom())
                            .get(0).toString());
            contexts.get().setOrgForReplyMsg(displayedMessage);
            SecHarry.setRoot("sendmail", SecHarry.CSS.UNICHORN);
        }

    }

    @FXML
    public void forward(ActionEvent event) throws IOException {
        if (displayedMessage != null) {
            contexts.get().getToAddresses().clear();
            contexts.get().setOrgForReplyMsg(displayedMessage);
            contexts.get().setForeward(true);
            SecHarry.setRoot("sendmail", SecHarry.CSS.UNICHORN);
        }
    }

    @FXML
    public void showCert(ActionEvent event) throws Exception {
        EReceiver.ReadableMail mail = new EReceiver.ReadableMail(displayedMessage, getPrivateKeyTuple());
        mail.analyzeContent(null);
        if (mail != null) {
            SigningBean bean = new SigningBean().setCheckPathOcsp(true);
            AlgorithmPathChecker checker = new AlgorithmPathChecker(ConfigReader.loadAllTrusts(), bean);
            X509Certificate[] chain = checker.detectChain(mail.getSigner(),
                    null, new VerifyUtil.SignerInfoCheckResults());
            if (chain.length > 2) {
                ShowCertsDialog.showCertChainDialog(chain);
            }
        }
    }

    @FXML
    public void showSig(ActionEvent event) throws Exception {
        EReceiver.ReadableMail mail = new EReceiver.ReadableMail(displayedMessage, getPrivateKeyTuple());
        mail.analyzeContent(null);
        if (mail != null) {
            SigningBean bean = new SigningBean().setCheckPathOcsp(true);
            AlgorithmPathChecker checker = new AlgorithmPathChecker(ConfigReader.loadAllTrusts(), bean);
            X509Certificate[] chain = checker.detectChain(mail.getSigner(),
                    null, new VerifyUtil.SignerInfoCheckResults());
            if (chain.length < 2) {
                signedBy.setText("cannot detect chain");
            } else {
                signedBy.setText(mail.getSigner().getSubjectDN().getName());
            }
        }
    }

    @FXML
    public void addresses(ActionEvent event) throws IOException {
        SecHarry.setRoot("addressbook", SecHarry.CSS.UNICHORN);
    }

    @FXML
    public void replyAll(ActionEvent event) {

    }

    @FXML
    public void back(ActionEvent event) throws Exception {
        for (Tuple<Session, Tuple<Store, Folder>> result: connectResult.values()) {
            result.getSecond().getFirst().close();
        }
        SecHarry.setRoot("main", SecHarry.CSS.UNICHORN);
    }

    @FXML
    public void newAccount(ActionEvent event) {
        Tuple<String, Tuple<String, String>> result = NewEmailAccountDialog.createAccountDialog();
        EmailClientConfiguration.newConfigItem(result.getSecond().getFirst(),
                result.getSecond().getSecond(),
                result.getFirst(), false);
        refreshTree();
    }

    private void refreshTree() {
        TreeItem<String> root = controlTree.getRoot();
        mailboxes = EmailClientConfiguration.getMailboxes();
        for (ImapConfigType box: mailboxes.getImapConfig()) {
            TreeItem<String> child = new TreeItem<>(box.getConfigName());
            ObservableList<TreeItem<String>> boxesList = root.getChildren();
            Optional<TreeItem<String>> item = boxesList.stream()
                    .filter(e -> e.getValue().equals(box.getEmailAddress()))
                    .findFirst();
            if (!item.isPresent()) {
                root.getChildren().add(child);
            }
            Tuple<Session, Tuple<Store, Folder>> connRes = connectResult.get(box.getEmailAddress());
            String password;
            if (connRes == null) {
                EMailConnector connector = new EMailConnector(box.getImapHost(),
                        Integer.parseInt(box.getImapPort()));
                Tuple<String, String> credentials = getEMailPasswd(box.getEmailAddress());
                if (credentials == null) {
                    password = ConfirmPasswordDialog.passwordStoreDialog(box.getEmailAddress());
                } else {
                    password = credentials.getSecond();
                }
                Tuple<Store, Folder> result = connector.connect(box.getEmailAddress(), password);
                Session resultSession = connector.getSession();
                connRes = new Tuple<>(resultSession, result);
                connectResult.put(box.getEmailAddress(), connRes);
            }
            Folder[] folders = IMAPUtils.listFolders(connRes.getSecond(), box.getEmailAddress());
            foldersMap.put(box.getEmailAddress(), folders);
            for(Folder folder: folders) {
                TreeItem<String> folderItem = new TreeItem<>(folder.getName());
                child.getChildren().add(folderItem);
            }
        }
        EmailClientConfiguration.storeMailboxes();
    }

    public static Tuple<String, String> getEMailPasswd(String email) {
        String password = System.getenv("credomail");
        if (password != null && password.length() >4) {
            PasswordManager manager = new PasswordManager(password);
            Tuple<String, String> result = manager.readPassword(email);
            return result;
        } else {
            return null;
        }
    }

    public static AccountConfig getMailBoxes() {
        return mailboxes;
    }

    public static Tuple<Store, Folder> getConnectParams(String email) {
        return connectResult.get(email).getSecond();
    }

    public void saveMessages(Message[] messages, String path) throws Exception {
        File base = new File(APP_DIR_EMAILER);
        File baseDirFile = null;
        Folder folder = null;
        long largestUid = 0;
        if (messages != null && messages.length >= 1) {
            folder = messages[0].getFolder();
            folder.open(Folder.READ_WRITE);
            largestUid = ((IMAPFolder)folder).getUIDNext() - 1;
        }
        for (Message msg: messages) {
            String dirName = path;
            baseDirFile = new File(base, dirName);
            String fName = UUID.randomUUID().toString() + ".msg";
            baseDirFile.mkdirs();
            File msgFile = new File(baseDirFile, fName);
            FileOutputStream out = new FileOutputStream(msgFile);
            msg.writeTo(out);
            out.close();
            messageMap.put(msgFile.getAbsolutePath(), msg);
        }
        if (folder != null) {
            folder.close(false);
        }
        if (baseDirFile != null && baseDirFile.exists()) {
            File intFile = new File(baseDirFile, PROP_FOLDERINDEXFILE);
            PrintWriter writer = new PrintWriter(new FileOutputStream(intFile));
            writer.print("" + largestUid);
            writer.close();
        }
    }

    public Map<String, Message> loadMessages(String path, Tuple<Session, Tuple<Store, Folder>> connection) throws Exception {
        Map<String, Message> messages = new LinkedHashMap<>();
        connection.getSecond().getSecond().open(Folder.READ_WRITE);
        File base = new File(APP_DIR_EMAILER);
        File baseDirFile = new File(base, path);
        File intFile = new File(baseDirFile, PROP_FOLDERINDEXFILE);
        if (intFile.exists()) {
            File [] files = baseDirFile.listFiles();
            int index = 0;
            for (File file: files) {
                if (file.getAbsolutePath().endsWith(".msg")) {
                    MimeMessage msg = new MimeMessage(connection.getFirst(), new FileInputStream(file));
                    messages.put(file.getAbsolutePath(), msg);
                }
            }
        }
        for (Map.Entry<String, Message> mesg: messages.entrySet()) {
            MimeMessage msg = (MimeMessage)mesg.getValue();
            msg.setFlag(Flags.Flag.SEEN, true);
            OutputStream out = new FileOutputStream(mesg.getKey());
            msg.writeTo(out);
            out.flush();
            out.close();
        }
        connection.getSecond().getSecond().close(false);
        return messages;
    }


}
