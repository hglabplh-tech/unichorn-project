package org.harry.security.fx;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TextField;
import org.harry.security.CMSSigner;
import org.harry.security.util.ConfigReader;
import org.harry.security.util.SigningUtil;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.certandkey.KeyStoreTool;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Enumeration;

import static org.harry.security.fx.util.Miscellaneous.*;

public class CertToolCtrl implements ControllerInit {

    File keyStoreStream = null;

    File dataInput = null;
    File outFile = null;


    public Scene init() {
        ComboBox actionBox = getComboBoxByFXID("action");
        actionBox.getItems().addAll(CMSSigner.Commands.values());
        Scene scene = actionBox.getScene();

        return scene;
    }


    @FXML
    private void processAction(ActionEvent event) throws IOException {
        SigningBean signingBean = SecHarry.contexts.get();
        TextField passwd= getTextFieldByFXID("keyStorePass");
        ComboBox aliasBox = getComboBoxByFXID("alias");
        String alias = (String)aliasBox.getSelectionModel().getSelectedItem();
        ComboBox actionBox = getComboBoxByFXID("action");
        CMSSigner.Commands action = (CMSSigner.Commands)actionBox.getSelectionModel().getSelectedItem();
        ConfigReader.saveProperties(ConfigReader.init());
        ConfigReader.MainProperties props = ConfigReader.loadStore();
        InputStream dataInputStream = null;

        CertWriterReader.KeyStoreBean bean = null;
        String outPathString = null;
        if (keyStoreStream != null && dataInput != null) {
            bean = CertWriterReader.loadSecrets(new FileInputStream(keyStoreStream),
                    props.getKeystoreType(),
                    passwd.getText(), alias);
            dataInputStream = new FileInputStream(dataInput);
            outPathString = outFile.getAbsolutePath();
        }
        signingBean.setKeyStoreBean(bean)
                .setAction(action)
                .setDataINFile(dataInput)
                .setDataIN(dataInputStream)
                .setDataINPath(dataInput)
                .setOutputPath(outPathString);
        SecHarry.contexts.set(signingBean);
        if (action.equals(CMSSigner.Commands.ENCRYPT) || action.equals(CMSSigner.Commands.SIGN)) {
            SecHarry.setRoot("signing");
        } else if (action.equals(CMSSigner.Commands.VERIFY_SIGNATURE)) {
            SecHarry.setRoot("verify");
        }
    }

    @FXML
    private void loadStore(ActionEvent event) throws IOException, KeyStoreException {
        SigningBean signingBean = SecHarry.contexts.get();
        TextField passwd= getTextFieldByFXID("keyStorePass");
        ComboBox aliasBox = getComboBoxByFXID("alias");
        ConfigReader.saveProperties(ConfigReader.init());
        ConfigReader.MainProperties props = ConfigReader.loadStore();
        KeyStore store = KeyStoreTool.loadStore(new FileInputStream(keyStoreStream),passwd.getText().toCharArray(), "JKS");
        Enumeration<String> aliases = store.aliases();
        while(aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            aliasBox.getItems().add(alias);
        }
    }


    @FXML
    public void selectOutPath(ActionEvent event) {
        String fxId = "outPath";
        outFile = showSaveDialog(event, fxId);
    }

    @FXML
    private void selectInput(ActionEvent event) {
        String fxId = "inputPath";

        dataInput = showOpenDialog(event, fxId);
    }
    @FXML
    private void cancelSigning(ActionEvent event) throws IOException {
        System.out.println("cancel");
    }
    @FXML
    private void selectPath(ActionEvent event) throws IOException {
        String fxId = "keyStorePath";
        keyStoreStream = showOpenDialog(event, fxId);

    }

    @FXML
    private void showStore(ActionEvent event) throws IOException {
        SecHarry.setRoot("certificates");
    }



    @FXML
    private void more(ActionEvent event) throws IOException {
        SecHarry.setRoot("crledit");
    }
    @FXML
    private void editProps(ActionEvent event) throws IOException {
        SecHarry.setRoot("properties");
    }

}