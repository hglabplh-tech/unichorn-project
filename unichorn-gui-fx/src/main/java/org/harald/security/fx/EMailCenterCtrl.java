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
import org.harry.security.util.mailer.EMailConnector;
import org.harry.security.util.mailer.EReceiver;
import org.harry.security.util.mailer.EmailClientConfiguration;
import org.harry.security.util.mailer.IMAPUtils;
import org.pmw.tinylog.Logger;
import security.harry.org.emailer._1.MailboxType;
import security.harry.org.emailer._1.Mailboxes;

import javax.activation.DataHandler;
import javax.mail.Address;
import javax.mail.Folder;
import javax.mail.Message;
import javax.mail.Store;

import java.io.File;
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

    @FXML
    WebView webContentView;



    @FXML
    ListView<String> mailList;

    Map<String, Tuple<Store, Folder>> connectResult = new HashMap<>();

    Map<String, Folder[]> foldersMap = new HashMap<>();

    List<Message> actualMessages = new ArrayList<>();

    public Scene init() {
        mailList.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<String>() {
            @Override
            public void changed(ObservableValue<? extends String> observableValue, String s, String t1) {
                ObservableList<Integer> indices = mailList.getSelectionModel().getSelectedIndices();
                if (indices.size() > 0) {
                    try {
                        int index = indices.get(0);
                        Message message = actualMessages.get(index);
                        EReceiver.ReadableMail mail = new EReceiver.ReadableMail(message);
                        mail.analyzeContent();
                        fromBox.getItems().clear();
                        fromBox.getItems().addAll(mail.getFromList());
                        subject.setText(message.getSubject());
                        WebEngine engine = webContentView.getEngine();
                        List<Tuple<String, DataHandler>> contentList = mail.getPartList();
                        if (contentList.size() > 0) {
                            InputStream stream = contentList.get(0).getSecond().getInputStream();
                            String content = IOUtils.toString(stream, Charset.defaultCharset());
                            engine.loadContent(content);
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
    public void writeMail(ActionEvent event) {

    }

    @FXML
    public void reply(ActionEvent event) {

    }

    @FXML
    public void forward(ActionEvent event) {

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
        EmailClientConfiguration.newMailbox(result.getSecond().getFirst(),
                result.getSecond().getSecond(),
                result.getFirst());
        refreshTree();
    }

    private void refreshTree() {
        TreeItem<String> root = controlTree.getRoot();
        Mailboxes mailboxes = EmailClientConfiguration.getMailboxes();
        for (MailboxType box: mailboxes.getMailbox()) {
            TreeItem<String> child = new TreeItem<>(box.getConfigName());
            ObservableList<TreeItem<String>> boxesList = root.getChildren();
            Optional<TreeItem<String>> item = boxesList.stream()
                    .filter(e -> e.getValue().equals(box.getEmailAddress()))
                    .findFirst();
            if (!item.isPresent()) {
                root.getChildren().add(child);
            }
            Tuple<Store, Folder> connRes = connectResult.get(box.getEmailAddress());
            if (connRes == null) {
                EMailConnector connector = new EMailConnector(box.getImapHost(),
                        Integer.parseInt(box.getImapPort()));
                String password = ConfirmPasswordDialog.passwordStoreDialog(box.getEmailAddress());
                connRes = connector.connect(box.getEmailAddress(), password);
                connectResult.put(box.getEmailAddress(), connRes);
            }
            Folder[] folders = IMAPUtils.listFolders(connRes.getSecond());
            foldersMap.put(box.getEmailAddress(), folders);
            for(Folder folder: folders) {
                TreeItem<String> folderItem = new TreeItem<>(folder.getName());
                child.getChildren().add(folderItem);
            }
        }
        EmailClientConfiguration.storeMailboxes();
    }
}
