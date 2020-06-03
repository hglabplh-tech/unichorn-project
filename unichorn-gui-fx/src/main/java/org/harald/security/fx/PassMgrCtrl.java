package org.harald.security.fx;

import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import org.harry.security.util.ConfigReader;
import org.harry.security.util.Tuple;
import org.harry.security.util.pwdmanager.PasswordManager;

import java.util.*;

import static org.harald.security.fx.util.MiscellaneousMgr.getTextFieldByFXID;

public class PassMgrCtrl implements ControllerInit {

    @FXML private TableView<PasswdEntry> propPassword;

    @Override
    public Scene init() {

        return null;
    }

    @FXML
    public void refresh(ActionEvent event) {
        TextField masterPass = getTextFieldByFXID("masterPass");
        propPassword.getSelectionModel().setCellSelectionEnabled(true);
        propPassword.setEditable(true);

        propPassword.getSelectionModel().getSelectedItem();

        List<PasswdEntry> entryList = new ArrayList<>();
        PasswordManager manager = new PasswordManager(masterPass.getText());
        Map<String, Tuple<String, String>> resultMap = manager.decryptStore();
        Set<String> keys = resultMap.keySet();
        for (String key: keys) {
            Tuple<String, String> value = resultMap.get(key);
            PasswdEntry entry = new PasswdEntry(key, value.getFirst(), value.getSecond());
            entryList.add(entry);
        }
        ObservableList<PasswdEntry> data = propPassword.getItems();
        data.clear();
        data.addAll(entryList);
        propPassword.getEditingCell();

        propPassword.setVisible(false);
        propPassword.refresh();
        propPassword.setVisible(true);
    }


    @FXML
    public void genPasswd(ActionEvent event) {
        TextField masterPass = getTextFieldByFXID("masterPass");
        String masterPW = masterPass.getText();
        StorePasswdDialog.passwordStoreDialog(masterPW, true);
    }

    @FXML
    public void create(ActionEvent event) {
        TextField masterPass = getTextFieldByFXID("masterPass");
        String masterPW = masterPass.getText();
        StorePasswdDialog.passwordStoreDialog(masterPW, false);
    }
}
