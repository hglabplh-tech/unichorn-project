package org.harald.security.fx;

import ezvcard.VCard;
import ezvcard.parameter.EmailType;
import ezvcard.property.Email;
import ezvcard.property.FormattedName;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.ListView;
import javafx.scene.control.TextField;
import org.harry.security.util.mailer.VCardHandler;
import org.pmw.tinylog.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.harry.security.CommonConst.APP_DIR_EMAILER;
import static org.harry.security.CommonConst.PROP_ADDRESSBOOK;


public class AddressBookCtrl implements ControllerInit {

    @FXML
    TextField firstName;

    @FXML
    TextField lastName;

    @FXML
    TextField nickName;

    @FXML
    TextField business;

    @FXML
    TextField private1;

    @FXML
    TextField private2;

    @FXML
    ListView<String> addr_list;

    private int actIndex = 0;

    List<VCard> vcardList = new ArrayList<>();

    @Override
    public Scene init() {
        File addrFile = new File(APP_DIR_EMAILER, PROP_ADDRESSBOOK);
        try {
            if (addrFile.exists()) {
                vcardList = VCardHandler.parseVCardXML(new FileInputStream(addrFile));
                for (VCard vcard : vcardList) {
                    String nickName = vcard.getFormattedNames().get(2).getValue();
                    addr_list.getItems().add(nickName);
                }

            }
            addr_list.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<String>() {
                @Override
                public void changed(ObservableValue<? extends String> observableValue, String s, String t1) {
                    ObservableList<Integer> indices = addr_list.getSelectionModel().getSelectedIndices();
                    if (indices.size() > 0) {
                        try {
                            int index = indices.get(0);
                            VCard vcard = vcardList.get(index);
                            List<FormattedName> names = vcard.getFormattedNames();
                            firstName.setText(names.get(0).getValue());
                            lastName.setText(names.get(1).getValue());
                            nickName.setText(names.get(2).getValue());
                            List<Email> emails = vcard.getEmails();
                            Optional<Email> work = getMailAddressByType(emails, EmailType.WORK);
                            Optional<Email> priv1 = getMailAddressByType(emails, EmailType.INTERNET);
                            Optional<Email> priv2 = getMailAddressByType(emails, EmailType.HOME);
                            if (work.isPresent()) {
                                business.setText(work.get().getValue());
                            } else {
                                business.setText("");
                            }
                            if (priv1.isPresent()) {
                                private1.setText(priv1.get().getValue());
                            } else {
                                private1.setText("");
                            }
                            if (priv2.isPresent()) {
                                private2.setText(priv2.get().getValue());
                            } else {
                                private2.setText("");
                            }
                        } catch (Exception ex) {

                        }
                    }
                }
            });

        } catch (Exception ex) {
            Logger.trace(ex);
            throw new IllegalStateException("init error", ex);
        }
        return null;
    }

    private Optional<Email> getMailAddressByType(List<Email> emails, EmailType type) {
        return emails.stream().filter(e -> e.getTypes().stream().anyMatch(t -> t.equals(type))).findFirst();
    }

    @FXML
    public void add(ActionEvent event) {
        addr_list.getItems().add("toSubst");
        actIndex = (addr_list.getItems().size() -1);
    }

    @FXML
    public void remove(ActionEvent event) {
        ObservableList<Integer> selected = addr_list.getSelectionModel().getSelectedIndices();
        if (selected.size() > 0) {
            addr_list.getItems().remove(selected.get(0));
            vcardList.remove(selected.get(0));
        }
    }

    @FXML
    public void save(ActionEvent event) throws IOException {
        addr_list.getItems().set(actIndex, nickName.getText());
        VCardHandler.addVCard(firstName.getText(), lastName.getText(),
                nickName.getText(), business.getText(),
                private1.getText(), private2.getText());
        File addrFile = new File(APP_DIR_EMAILER, PROP_ADDRESSBOOK);
        VCardHandler.writeVCardXML(new FileOutputStream(addrFile));
    }

    @FXML
    public void back(ActionEvent event) throws IOException {
        SecHarry.setRoot("emailer", SecHarry.CSS.UNICHORN);
    }
}
