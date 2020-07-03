package org.harald.security.fx;

import ezvcard.VCard;
import ezvcard.parameter.VCardParameter;
import ezvcard.parameter.VCardParameters;
import ezvcard.property.Nickname;
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
        } catch (Exception ex) {
            Logger.trace(ex);
            throw new IllegalStateException("init error", ex);
        }
        return null;
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
