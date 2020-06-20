package org.harald.security.fx;

import iaik.x509.X509Certificate;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TextField;
import org.harry.security.CMSSigner;
import org.harry.security.util.CertificateWizzard;
import org.harry.security.util.ConfigReader;
import org.harry.security.util.Tuple;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.CSRHandler;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.httpclient.HttpClientConnection;
import org.harry.security.util.trustlist.TrustListManager;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.util.Enumeration;
import java.util.List;

import static org.harald.security.fx.util.Miscellaneous.*;
import static org.harry.security.CommonConst.*;
import static org.harry.security.util.CertificateWizzard.*;

public class CertToolCtrl implements ControllerInit {

    File keyStoreFile = null;

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
        if (keyStoreFile != null && dataInput != null) {
            // TODO have to change next two lines for loading a specific store
            KeyStore store = KeyStoreTool.loadStore(new FileInputStream(keyStoreFile),
                    passwd.getText().toCharArray(), "PKCS12");
            Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool
                    .getKeyEntry(store, alias, passwd.getText().toCharArray());
            bean = new CertWriterReader.KeyStoreBean(keys.getSecond(), keys.getFirst());
        }
        if (dataInput != null) {
            dataInputStream = new FileInputStream(dataInput);
        }
        if (outFile != null) {
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
            SecHarry.setRoot("signing", SecHarry.CSS.ABBY);
        } else if (action.equals(CMSSigner.Commands.VERIFY_SIGNATURE)) {
            SecHarry.setRoot("verify", SecHarry.CSS.UNICHORN);
        } else if (action.equals(CMSSigner.Commands.GEN_KEYSTORE)) {
            CertificateWizzard.generateThis();
        }
    }

    @FXML
    private void loadStore(ActionEvent event) throws IOException, KeyStoreException {
        TextField passwd= getTextFieldByFXID("keyStorePass");
        ComboBox aliasBox = getComboBoxByFXID("alias");
        ConfigReader.saveProperties(ConfigReader.init());
        ConfigReader.MainProperties props = ConfigReader.loadStore();
        KeyStore store = KeyStoreTool.loadStore(new FileInputStream(keyStoreFile),passwd.getText().toCharArray(), "PKCS12");
        Enumeration<String> aliases = store.aliases();
        while(aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            aliasBox.getItems().add(alias);
        }
    }

    @FXML
    private void initKeys(ActionEvent event) throws Exception {
        SigningBean signingBean = SecHarry.contexts.get();
        File keystore = new File(APP_DIR, PROP_STORE_NAME);
        File trustFile = new File(APP_DIR_TRUST, PROP_TRUST_NAME);
        keystore.delete();
        trustFile.delete();
        initThis();
        ConfigReader.MainProperties mainProps = ConfigReader.loadStore();
        File propFile = new File(APP_DIR, PROP_FNAME);
        CSRHandler.initAppKeystore(keystore, trustFile, propFile);
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        signingBean.setWalker(walkers);
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
        SecHarry.setRoot("crledit", SecHarry.CSS.ABBY);
    }

    @FXML
    public void signxades(ActionEvent event) throws IOException {
        SecHarry.setRoot("signingXAdES", SecHarry.CSS.UNICHORN);
    }
    @FXML
    private void selectPath(ActionEvent event) throws IOException {
        String fxId = "keyStorePath";
        keyStoreFile = showOpenDialog(event, fxId);

    }

    @FXML
    private void uploadStore(ActionEvent event) throws Exception {
        TextField passwd= getTextFieldByFXID("keyStorePass");
        HttpClientConnection.sendPutData(new FileInputStream(keyStoreFile), "pkcs12", passwd.getText());

    }

    @FXML
    private void showStore(ActionEvent event) throws IOException {
        SecHarry.setRoot("certificates", SecHarry.CSS.ABBY);
    }

    @FXML
    private void manageCard(ActionEvent event) throws IOException {
        SecHarry.setRoot("cardData", SecHarry.CSS.UNICHORN);
    }

    @FXML
    private void createAttrCert(ActionEvent event) throws IOException {
        SecHarry.setRoot("attrCert", SecHarry.CSS.UNICHORN);
    }



    @FXML
    private void more(ActionEvent event) throws IOException {
        //SecHarry.setRoot("crledit", SecHarry.CSS.ABBY);
        SecHarry.setRoot("trustEdit", SecHarry.CSS.ABBY);
    }

    @FXML
    private void browser(ActionEvent event) throws IOException {
        //SecHarry.setRoot("crledit", SecHarry.CSS.ABBY);
        SecHarry.setRoot("browser", SecHarry.CSS.UNICHORN);
    }

    @FXML
    private void editProps(ActionEvent event) throws IOException {
        SecHarry.setRoot("properties", SecHarry.CSS.UNICHORN);
    }

}