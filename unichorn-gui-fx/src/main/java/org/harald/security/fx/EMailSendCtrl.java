package org.harald.security.fx;

import ezvcard.VCard;
import ezvcard.property.Email;
import iaik.x509.X509Certificate;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.cell.TextFieldListCell;
import javafx.scene.web.HTMLEditor;
import javafx.util.Callback;
import javafx.util.StringConverter;
import org.apache.commons.io.IOUtils;
import org.harald.security.fx.util.Miscellaneous;
import org.harry.security.util.Tuple;
import org.harry.security.util.mailer.EReceiver;
import org.harry.security.util.mailer.ESender;
import org.harry.security.util.mailer.VCardHandler;
import org.pmw.tinylog.Logger;
import security.harry.org.emailer._1.AccountConfig;
import security.harry.org.emailer._1.ImapConfigType;
import security.harry.org.emailer._1.SmtpConfigType;


import javax.activation.DataHandler;
import javax.mail.Folder;
import javax.mail.Message;
import javax.mail.Store;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.harald.security.fx.util.Miscellaneous.*;
import static org.harry.security.CommonConst.APP_DIR_EMAILER;
import static org.harry.security.CommonConst.PROP_ADDRESSBOOK;

public class EMailSendCtrl implements ControllerInit {

    @FXML
    ComboBox<String> from;

    @FXML
    ListView<String> toBox;

    @FXML
    HTMLEditor content;

    @FXML
    TextField subject;

    @FXML ListView<String> attachments;

    @FXML CheckBox sign;

    @FXML CheckBox encrypt;


    private Message forwardMessage = null;

    List<File> attachmentFiles = new ArrayList<>();

    List<VCard> vcardList = new ArrayList<>();


    AccountConfig mailboxes;
    @Override
    public Scene init() {
        forwardMessage = null;
        List<String> to = contexts.get().getToAddresses();
        File addrFile = new File(APP_DIR_EMAILER, PROP_ADDRESSBOOK);
        try {
            if (addrFile.exists()) {
                vcardList = VCardHandler.parseVCardXML(new FileInputStream(addrFile));
            }
        } catch (Exception ex) {
            Logger.trace(ex);
            throw new IllegalStateException("init error", ex);
        }
        mailboxes = EMailCenterCtrl.getMailBoxes();
        for (ImapConfigType box: mailboxes.getImapConfig()) {
            if (box.getEmailAddress() != null) {
                from.getItems().add(box.getEmailAddress());
            }

        }
        Message temp = contexts.get().getOrgForReplyMsg();
        if (temp != null) {
            try {
                if (contexts.get().isForeward()) {
                    forwardMessage = temp;
                    Tuple<PrivateKey, X509Certificate[]> keys = Miscellaneous.getPrivateKeyTuple();
                    EReceiver.ReadableMail mail = new EReceiver.ReadableMail(forwardMessage, keys);
                    mail.analyzeContent(null);
                    List<String> fromAddr = mail.getToList();
                    from.getItems().add(fromAddr.get(0));
                    from.getSelectionModel().select(from.getItems().size() - 1);
                    List<Tuple<String, DataHandler>> displayContentList = mail.getPartList();
                    if (displayContentList.size() > 0) {
                        Tuple<String, DataHandler> displayContent = displayContentList.get(0);
                        String text = IOUtils.toString(displayContent.getSecond().getInputStream());
                        String messageText = "---------- Original Message----------------\\\n"
                                + "From:" + forwardMessage.getFrom()[0].toString()
                                + "\\\n ---------------------------------- "
                                + text;
                        content.setHtmlText(messageText);
                        subject.setText("FWD: " + forwardMessage.getSubject());
                    }

                } else {
                    toBox.getItems().addAll(to);
                    contexts.get().getToAddresses().clear();
                    Message orig = temp;
                    Tuple<PrivateKey, X509Certificate[]> keys = Miscellaneous.getPrivateKeyTuple();
                    EReceiver.ReadableMail mail = new EReceiver.ReadableMail(orig, keys);
                    mail.analyzeContent(null);
                    List<String> fromAddr = mail.getToList();
                    from.getItems().add(fromAddr.get(0));
                    from.getSelectionModel().select(from.getItems().size() - 1);
                    List<Tuple<String, DataHandler>> displayContentList = mail.getPartList();
                    if (displayContentList.size() > 0) {
                        Tuple<String, DataHandler> displayContent = displayContentList.get(0);
                        String text = IOUtils.toString(displayContent.getSecond().getInputStream());
                        String messageText = "---------- Original Message----------------\\\n"
                                + "From:" + orig.getFrom()[0].toString()
                                + "\\\n at " + orig.getSentDate().toString()
                                + "\\\n ---------------------------------- "
                                + text;
                        content.setHtmlText(messageText);
                        subject.setText("RE: " + orig.getSubject());
                    }
                }
                } catch(Exception ex){
                    throw new IllegalStateException("reply msg build failed", ex);
                }

        } else {
            from.getSelectionModel().select(0);
        }
        toBox.setCellFactory(new Callback<ListView<String>, ListCell<String>>() {

            @Override
            public ListCell<String> call(ListView<String> param) {
                return new TextFieldListCell<String>(new StringConverter<String>() {

                    @Override
                    public String toString(String input) {
                        Optional<VCard> vCard = VCardHandler.findVCard(input);
                        if (vCard.isPresent()) {
                            input = vCard.get().getEmails().get(0).getValue();
                        }
                        return input;
                    }

                    @Override
                    public String fromString(String input) {
                        return input;
                    }

                });
            }
        });

        toBox.setEditable(true);
        contexts.get().setForeward(false);
        contexts.get().setOrgForReplyMsg(null);
        return from.getScene();
    }

    @FXML
    public void addAttachment(ActionEvent event) {
        File attachment = showOpenDialogButton(event, attachments);
        if (attachment != null) {
            attachmentFiles.add(attachment);
        }
    }

    @FXML
    public void sendMail(ActionEvent event) throws Exception {

        String temp1 = from.getSelectionModel().getSelectedItem();

        Optional<ImapConfigType> box =
                mailboxes.getImapConfig()
                        .stream()
                        .filter(e -> temp1.equals(e.getEmailAddress()))
                        .findFirst();
        if (!box.isPresent()) {
            String  temp2 = from.getItems().get(0);
            box = mailboxes.getImapConfig()
                            .stream()
                            .filter(e -> temp2.equals(e.getEmailAddress()))
                            .findFirst();
        }
        String email = (box.isPresent()) ? box.get().getEmailAddress() : null;
        if (box.isPresent() && email != null) {
            ImapConfigType selected = box.get();
            Tuple<Store, Folder> connParms =  EMailCenterCtrl.getConnectParams(selected.getEmailAddress());
            SmtpConfigType smtpParams = getSmtpParams(mailboxes);
            ESender.Builder builder = ESender.newBuilder(connParms.getFirst(),
                    connParms.getSecond(),
                    smtpParams.getSmtpHost(),
                    smtpParams.getSmtpPort(), getPrivateKeyTuple()).setSubject(subject.getText()).setFrom(email);

            for (String toEmail :toBox.getItems()) {
                String mailAddr = toEmail;
                Optional<VCard> vcardOpt = VCardHandler.findVCard(toEmail);
                if (vcardOpt.isPresent()) {
                    List<Email> emails = vcardOpt.get().getEmails();
                    for (Email mail: emails) {
                        if (mail != null) {
                            mailAddr = mail.getValue();
                            if (mailAddr != null && mailAddr.contains("@")) {
                                builder.addTo(mailAddr);
                            }
                        }
                    }
                } else {
                    builder.addTo(mailAddr);
                }
            }
            if (attachmentFiles.size() > 0) {
                builder.setAttachements(attachmentFiles);
            }
            ESender sender = builder.setText(content.getHtmlText()).build();
            Tuple<String, String> credentials = EMailCenterCtrl.getEMailPasswd(smtpParams.getEmailAddress());
            String password;
            if (credentials == null) {
                password = ConfirmPasswordDialog.passwordStoreDialog(email);
            } else {
                password = credentials.getSecond();
            }
            if (sign.isSelected() && encrypt.isSelected()) {
                sender.sendSignedAndEncrypted(smtpParams
                                .getEmailAddress(), password);
            } else if (sign.isSelected()) {
                sender.sendSigned(smtpParams
                        .getEmailAddress(), password);
            } else {
                if (forwardMessage != null) {
                    sender.forwardMessageTo(smtpParams
                            .getEmailAddress(), password, forwardMessage, true);
                } else {
                    sender.sendEmail(smtpParams
                            .getEmailAddress(), password);
                }
            }
        }
    }

    @FXML
    public void cancel(ActionEvent event) throws IOException  {
        SecHarry.setRoot("emailer", SecHarry.CSS.UNICHORN);
    }

    @FXML
    public void addTo(ActionEvent event) {
        toBox.getItems().add("");
        toBox.edit(toBox.getItems().size() -1);
    }

    private SmtpConfigType getSmtpParams(AccountConfig mailboxes) {
        Optional<SmtpConfigType> mType = mailboxes.getSmtpConfig()
                .stream()
                .filter(e -> e.isDefault()).findFirst();
        return mType.get();
    }
}
