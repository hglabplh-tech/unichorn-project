package org.harald.security.fx;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.cell.TextFieldListCell;
import javafx.util.Callback;
import javafx.util.StringConverter;
import org.harry.security.util.Tuple;
import org.harry.security.util.mailer.ESender;
import security.harry.org.emailer._1.AccountConfig;
import security.harry.org.emailer._1.ImapConfigType;
import security.harry.org.emailer._1.SmtpConfigType;


import javax.mail.Folder;
import javax.mail.Store;
import java.io.IOException;
import java.util.Optional;

public class EMailSendCtrl implements ControllerInit {

    @FXML
    ComboBox<String> from;

    @FXML
    ListView<String> toBox;

    @FXML
    TextArea content;

    @FXML
    TextField subject;


    AccountConfig mailboxes;
    @Override
    public Scene init() {
        mailboxes = EMailCenterCtrl.getMailBoxes();
        for (ImapConfigType box: mailboxes.getImapConfig()) {
            if (box.getEmailAddress() != null) {
                from.getItems().add(box.getEmailAddress());
            }

        }
        toBox.setCellFactory(new Callback<ListView<String>, ListCell<String>>() {

            @Override
            public ListCell<String> call(ListView<String> param) {
                return new TextFieldListCell<String>(new StringConverter<String>() {

                    @Override
                    public String toString(String input) {
                        return input;
                    }

                    @Override
                    public String fromString(String input) {
                        return input;
                    }

                });
            }
        });
        from.getSelectionModel().select(0);
        content.setEditable(true);
        toBox.setEditable(true);
        return from.getScene();
    }

    @FXML
    public void sendMail(ActionEvent event) {
        String email = from.getSelectionModel().getSelectedItem();
        Optional<ImapConfigType> box =
                mailboxes.getImapConfig()
                        .stream()
                        .filter(e -> email.equals(e.getEmailAddress()))
                        .findFirst();
        if (box.isPresent()) {
            ImapConfigType selected = box.get();
            Tuple<Store, Folder> connParms =  EMailCenterCtrl.getConnectParams(selected.getEmailAddress());
            SmtpConfigType smtpParams = getSmtpParams(mailboxes);
            ESender.Builder builder = ESender.newBuilder(connParms.getFirst(),
                    connParms.getSecond(),
                    smtpParams.getSmtpHost(),
                    smtpParams.getSmtpPort()).setSubject(subject.getText()).setFrom(email);
            for (String toEmail :toBox.getItems()) {
                builder.addTo(toEmail);
            }
            ESender sender = builder.setText(content.getText()).build();
            Tuple<String, String> credentials = EMailCenterCtrl.getEMailPasswd(smtpParams.getEmailAddress());
            String password;
            if (credentials == null) {
                password = ConfirmPasswordDialog.passwordStoreDialog(email);
            } else {
                password = credentials.getSecond();
            }
            sender.sendEmail(smtpParams.getEmailAddress(), password);
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
