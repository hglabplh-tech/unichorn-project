package org.harald.security.fx;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ListView;
import javafx.scene.control.TextField;
import org.harald.security.fx.util.Miscellaneous;
import org.harry.security.util.Tuple;
import org.harry.security.util.mailer.EmailClientConfiguration;
import security.harry.org.emailer_client._1.ClientConfig;
import security.harry.org.emailer_client._1.CryptoConfigType;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.harry.security.CommonConst.*;

public class EMailClientConfCtrl implements ControllerInit{

    @FXML
    CheckBox smartCardSel;

    @FXML
    TextField password;

    @FXML
    TextField storeLoc;

    @FXML
    TextField alias;

    @FXML
    TextField name;

    @FXML
    ListView<String> cryptoConfList;

    @FXML TextField selConfigName;

    ClientConfig config = null;

    List<CryptoConfigType> cryptoConfigs = new ArrayList<>();

    @Override
    public Scene init() {
        Tuple<String, String> confPassword = EMailCenterCtrl.getEMailPasswd("emailCryptoConf");
        config = EmailClientConfiguration.loadClientConf(confPassword.getSecond());
        cryptoConfigs = config.getCryptoConfig();
        for (CryptoConfigType cryptoConf: cryptoConfigs) {
            cryptoConfList.getItems().add(cryptoConf.getName());
        }
        cryptoConfList.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<String>() {
            @Override
            public void changed(ObservableValue<? extends String> observableValue, String s, String newVal) {
                Optional<CryptoConfigType> actConf = cryptoConfigs.stream()
                        .filter(e -> e.getName().equals(newVal))
                        .findFirst();
                if (actConf.isPresent()) {
                    selConfigName.setText(config.getCryptoConfigName());
                    storeLoc.setText(actConf.get().getKeyStoreFile());
                    alias.setText(actConf.get().getAlias());
                    name.setText(actConf.get().getName());
                    password.setText(actConf.get().getPassword());
                    if (storeLoc.getText().equals("::SMARTCARD::")) {
                        smartCardSel.setSelected(true);
                    } else {
                        smartCardSel.setSelected(false);
                    }
                }
            }
        });

        return cryptoConfList.getScene();
    }

    @FXML
    public void selectStore(ActionEvent event) {
        File dummy = Miscellaneous.showOpenDialog(event, storeLoc);
    }

    @FXML
    public void smartCardSel(ActionEvent event) {

    }

    @FXML
    public void clear(ActionEvent event) {
        storeLoc.setText("");
        alias.setText("");
        name.setText("");
        password.setText("");
        smartCardSel.setSelected(false);
    }

    @FXML
    public void back(ActionEvent event) throws IOException {
        SecHarry.setRoot("main", SecHarry.CSS.UNICHORN);
    }

    @FXML
    public void save(ActionEvent event)  throws IOException {
        config.setCryptoConfigName(selConfigName.getText());
        Tuple<String, String> credentials = EMailCenterCtrl.getEMailPasswd("emailCryptoConf");
        EmailClientConfiguration.storeClientConf(config, credentials.getSecond());
    }

    @FXML
    public void newEntry(ActionEvent event) throws IOException {
        CryptoConfigType cryptoNew = new CryptoConfigType();
        if (smartCardSel.isSelected()) {
            cryptoNew.setKeyStoreFile("::SMARTCARD::");
            cryptoNew.setAlias("");
            cryptoNew.setName(name.getText());
            cryptoNew.setPassword(password.getText());
        } else {
            cryptoNew.setName(name.getText());
            cryptoNew.setKeyStoreFile(storeLoc.getText());
            cryptoNew.setAlias(alias.getText());
            cryptoNew.setPassword(password.getText());
        }

        Optional<CryptoConfigType> found = cryptoConfigs.stream()
                .filter(e -> e.getName().equals(cryptoNew.getName()))
                .findFirst();
        if (found.isPresent()) { // replace
            int index = cryptoConfigs.indexOf(found.get());
            cryptoConfigs.set(index, cryptoNew);
        } else {
            cryptoConfigs.add(cryptoNew);
        }
    }
}
