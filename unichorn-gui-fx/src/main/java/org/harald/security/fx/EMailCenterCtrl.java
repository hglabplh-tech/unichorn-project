package org.harald.security.fx;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.*;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.ListView;
import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeView;
import org.harry.security.util.Tuple;
import org.harry.security.util.mailer.EMailConnector;
import org.harry.security.util.mailer.EReceiver;
import org.harry.security.util.mailer.EmailClientConfiguration;
import org.harry.security.util.mailer.IMAPUtils;
import org.pmw.tinylog.Logger;
import security.harry.org.emailer._1.MailboxType;
import security.harry.org.emailer._1.Mailboxes;

import javax.mail.Address;
import javax.mail.Folder;
import javax.mail.Message;
import javax.mail.Store;

import java.util.*;

public class EMailCenterCtrl implements ControllerInit {

    @FXML
    TreeView<String> controlTree;

    @FXML
    ListView<String> mailList;

    String actualEmail = null;

    Map<String, Tuple<Store, Folder>> connectResult = new HashMap<>();

    Map<String, Folder[]> foldersMap = new HashMap<>();

    public Scene init() {
        controlTree.getSelectionModel().selectedItemProperty()
                .addListener(new ChangeListener<TreeItem<String>>() {

                    @Override
                    public void changed(
                            ObservableValue<? extends TreeItem<String>> observable,
                            TreeItem<String> old_val, TreeItem<String> new_val) {
                        Folder[] folders = foldersMap.get(actualEmail);
                        Tuple<Store, Folder> login = connectResult.get(actualEmail);
                        List<String> mailEntries = new ArrayList<>();
                        TreeItem<String> selectedItem = new_val;
                        Optional<Folder> selected =
                                Arrays.stream(folders)
                                        .filter(e -> e.getName().equals(new_val.getValue()))
                                .findFirst();
                        if (selected.isPresent()) {
                            EReceiver receiver = new EReceiver(new Tuple<Store,Folder>(login.getFirst(),
                                    selected.get()));
                            Message[] messages = receiver.receiveMails();
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
            actualEmail = box.getEmailAddress();
            TreeItem<String> child = new TreeItem<>(box.getConfigName());
            root.getChildren().add(child);
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
