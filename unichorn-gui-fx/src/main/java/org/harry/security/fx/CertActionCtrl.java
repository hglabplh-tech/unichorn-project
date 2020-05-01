package org.harry.security.fx;

import iaik.x509.X509Certificate;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import org.harry.security.util.CertificateWizzard;
import org.harry.security.util.ConfigReader;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.certandkey.KeyStoreTool;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import static org.harry.security.fx.util.Miscellaneous.*;

public class CertActionCtrl implements ControllerInit {

    private X509Certificate actualCert = null;

    private InputStream sourceStream = null;

    private OutputStream targetStream = null;

    private InputStream storeStream = null;

    @Override
    public Scene init() {
        ComboBox impBox = getComboBoxByFXID("impFormat");
        impBox.getItems().addAll(CertWriterReader.CertType.values());
        ComboBox expBox = getComboBoxByFXID("expFormat");
        expBox.getItems().addAll(CertWriterReader.CertType.values());
        ComboBox typeBox = getComboBoxByFXID("keyStoreType");
        typeBox.getItems().addAll(KeyStoreTool.StoreType.values());
        return expBox.getScene();
    }

    @FXML
    protected void importCert(ActionEvent event) throws IOException, CertificateException {
        ComboBox impBox = getComboBoxByFXID("impFormat");
        ComboBox typeBox = getComboBoxByFXID("keyStoreType");
        TextField passwd = getTextFieldByFXID("passwd");
        TextField alias = getTextFieldByFXID("alias");
        KeyStoreTool.StoreType storeType = (KeyStoreTool.StoreType)
                typeBox.getSelectionModel().getSelectedItem();
        CertWriterReader.CertType certType = (CertWriterReader.CertType)
                impBox.getSelectionModel().getSelectedItem();
        if (certType.equals(CertWriterReader.CertType.PEM)) {
            CertWriterReader reader = new CertWriterReader();
            actualCert = reader.readFromFilePEM(sourceStream);
            TextArea area = getTextAreaByFXID("certView");
            area.setWrapText(true);
            area.setText(actualCert.toString());


        }else if (certType.equals(CertWriterReader.CertType.X509)) {
            CertWriterReader reader = new CertWriterReader();
            actualCert = reader.readX509(sourceStream);
            TextArea area = getTextAreaByFXID("certView");
            area.setWrapText(true);
            area.setText(actualCert.toString());


        } else if (certType.equals(CertWriterReader.CertType.P12)) {
        KeyStore store = null;
        if (storeStream !=null) {
            store = KeyStoreTool.loadStore(storeStream,
                    passwd.getText().toCharArray(),
                    storeType.getType());
            actualCert = KeyStoreTool.getCertificateEntry(store, alias.getText());
            TextArea area = getTextAreaByFXID("certView");
            area.setWrapText(true);
            area.setText(actualCert.toString());
        }

        }
    }

    @FXML
    protected void genChain(ActionEvent event) throws KeyStoreException, IOException {
        ComboBox typeBox = getComboBoxByFXID("keyStoreType");
        TextField passwd = getTextFieldByFXID("passwd");
        TextField alias = getTextFieldByFXID("alias");
        KeyStoreTool.StoreType storeType = (KeyStoreTool.StoreType)
                typeBox.getSelectionModel().getSelectedItem();
        ConfigReader.MainProperties props = ConfigReader.loadStore();
        props.setKeystorePass(passwd.getText());
            CertificateWizzard wizzard = new CertificateWizzard(ConfigReader.loadStore());
            wizzard.generateCA();
            wizzard.generateIntermediate();
            wizzard.generateUser();
            KeyStore store = wizzard.getStore();
            Enumeration<String> aliases = store.aliases();
            if (aliases.hasMoreElements()) {
                alias.setText(aliases.nextElement());
            }
            File outFile = showSaveDialogFromButton(event, "expTarget");
            KeyStoreTool.storeKeyStore(store, new FileOutputStream(outFile), passwd.getText().toCharArray());
            actualCert = KeyStoreTool.getCertificateEntry(store, alias.getText());
            TextArea area = getTextAreaByFXID("certView");
            area.setWrapText(true);
            area.setText(actualCert.toString());

    }

    @FXML
    protected void exportCert(ActionEvent event) throws IOException, CertificateEncodingException {
        ComboBox expBox = getComboBoxByFXID("expFormat");
        ComboBox typeBox = getComboBoxByFXID("keyStoreType");
        TextField passwd = getTextFieldByFXID("passwd");
        TextField alias = getTextFieldByFXID("alias");
        if (actualCert !=null) {
            CertWriterReader.CertType certType = (CertWriterReader.CertType)
                    expBox.getSelectionModel().getSelectedItem();
             KeyStoreTool.StoreType storeType = (KeyStoreTool.StoreType)
                    typeBox.getSelectionModel().getSelectedItem();
            if (certType.equals(CertWriterReader.CertType.PEM) && targetStream !=null) {
                CertWriterReader reader = new CertWriterReader(actualCert);
                reader.writeToFilePEM(targetStream);
            }else if (certType.equals(CertWriterReader.CertType.X509) && targetStream !=null) {
                CertWriterReader reader = new CertWriterReader(actualCert);
                reader.writeX509(targetStream);
            } else if (certType.equals(CertWriterReader.CertType.P12)) {
                KeyStore store = null;
                if (storeStream !=null) {
                   store = KeyStoreTool.loadStore(storeStream,
                           passwd.getText().toCharArray(),
                           storeType.getType());
                } else {
                   store =  KeyStoreTool.initStore(storeType.getType());
                }
                File outFile = showSaveDialogFromButton(event, "expTarget");
                targetStream = new FileOutputStream(outFile);
                KeyStoreTool.addCertificate(store, actualCert, alias.getText());
                KeyStoreTool.storeKeyStore(store, targetStream, passwd.getText().toCharArray());
            }
        }

    }

    @FXML
    public void selectFile(ActionEvent event) throws IOException {
        File selectedFile = showOpenDialog(event, "impSource");
        sourceStream = new FileInputStream(selectedFile);
    }

    @FXML
    public void selectTarget(ActionEvent event) throws IOException {
        File outFile = showSaveDialog(event, "expTarget");
        targetStream = new FileOutputStream(outFile);
    }

    @FXML
    public void selectStore(ActionEvent event) throws IOException {
        File inFile = showOpenDialog(event, "storeFile");
        storeStream = new FileInputStream(inFile);
    }

    @FXML
    protected void goBack(ActionEvent event) throws IOException, CertificateEncodingException {
        SecHarry.setRoot("certificates", SecHarry.CSS.ABBY);
    }
}
