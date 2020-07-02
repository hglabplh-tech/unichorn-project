package org.harald.security.fx;

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
import org.harry.security.util.Tuple;
import org.harry.security.util.mailer.*;
import org.harry.security.util.pwdmanager.PasswordManager;
import org.pmw.tinylog.Logger;
import security.harry.org.emailer._1.AccountConfig;
import security.harry.org.emailer._1.ImapConfigType;


import javax.activation.DataHandler;
import javax.mail.Address;
import javax.mail.Folder;
import javax.mail.Message;
import javax.mail.Store;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.*;

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
    static Map<String, Tuple<Store, Folder>> connectResult = new HashMap<>();

    Map<String, Folder[]> foldersMap = new HashMap<>();

    List<Message> actualMessages = new ArrayList<>();

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
                        displayedMessage = actualMessages.get(index);
                        EReceiver.ReadableMail mail = new EReceiver.ReadableMail(displayedMessage);
                        mail.analyzeContent();
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
                            Tuple<Store, Folder> login = connectResult.get(key);
                            List<String> mailEntries = new ArrayList<>();
                            Optional<Folder> selected =
                                    Arrays.stream(folders)
                                            .filter(e -> e.getName().equals(new_val.getValue()))
                                    .findFirst();
                            if (selected.isPresent()) {
                                EReceiver receiver = new EReceiver(new Tuple<Store, Folder>(login.getFirst(),
                                        selected.get()));
                                Message[] messages = receiver.receiveMails();
                                actualMessages.clear();
                                actualMessages.addAll(Arrays.asList(messages));
                                try {
                                    for (Message msg : messages) {
                                        Address[] from = msg.getFrom();
                                        StringBuffer buf = new StringBuffer();
                                        for (Address addr : from) {
                                            buf.append(addr.toString() + " , ");
                                        }
                                        mailEntries.add(msg.getSubject() + ";;" + buf.toString());
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
    public void reply(ActionEvent event) {

    }

    @FXML
    public void forward(ActionEvent event) {

    }

    @FXML
    public void showSig(ActionEvent event) {
        EReceiver.ReadableMail mail = new EReceiver.ReadableMail(displayedMessage);
        mail.analyzeContent();
        if (mail != null) {
            signedBy.setText(mail.getSigner().getSubjectDN().getName());
        }
    }

    @FXML
    public void addresses(ActionEvent event) {

    }

    @FXML
    public void replyAll(ActionEvent event) {

    }

    @FXML
    public void back(ActionEvent event) throws Exception {
        for (Tuple<Store, Folder> result: connectResult.values()) {
            result.getFirst().close();
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
            Tuple<Store, Folder> connRes = connectResult.get(box.getEmailAddress());
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
                connRes = connector.connect(box.getEmailAddress(), password);
                connectResult.put(box.getEmailAddress(), connRes);
            }
            Folder[] folders = IMAPUtils.listFolders(connRes, box.getEmailAddress());
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
        return connectResult.get(email);
    }


}
