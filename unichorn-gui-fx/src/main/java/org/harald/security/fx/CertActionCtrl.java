package org.harald.security.fx;

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
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import static org.harald.security.fx.util.Miscellaneous.*;

public class CertActionCtrl implements ControllerInit {

    private X509Certificate actualCert = null;

    private InputStream sourceStream = null;

    private OutputStream targetStream = null;


    private File storeFile;

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
        ComboBox aliases = getComboBoxByFXID("aliases");
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
        if (storeFile !=null) {
            store = KeyStoreTool.loadStore(new FileInputStream(storeFile),
                    passwd.getText().toCharArray(),
                    storeType.getType());
            String alias = (String)aliases.getSelectionModel().getSelectedItem();
            actualCert = KeyStoreTool.getCertificateEntry(store, alias);
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
        ComboBox aliases = getComboBoxByFXID("aliases");
        KeyStoreTool.StoreType storeType = (KeyStoreTool.StoreType)
                typeBox.getSelectionModel().getSelectedItem();
        ConfigReader.MainProperties props = ConfigReader.loadStore();
        props.setKeystorePass(passwd.getText());
        FileOutputStream stream = new FileOutputStream(props.getAttrCertPath());
        CertificateWizzard wizzard = new CertificateWizzard(props, stream);
        KeyPair caKeys = wizzard.generateCA(props.getCommonName(), true);
        KeyPair interKeys = wizzard.generateIntermediate(caKeys, props.getCommonName(), true);
        wizzard.generateUser(interKeys, props.getCommonName(), true);
            KeyStore store = wizzard.getStore();
            File outFile = showSaveDialogFromButton(event, "expTarget");
            KeyStoreTool.storeKeyStore(store, new FileOutputStream(outFile), passwd.getText().toCharArray());
            String alias = (String)aliases.getSelectionModel().getSelectedItem();
            actualCert = KeyStoreTool.getCertificateEntry(store, alias);
            TextArea area = getTextAreaByFXID("certView");
            area.setWrapText(true);
            area.setText(actualCert.toString());

    }

    @FXML
    protected void exportCert(ActionEvent event) throws IOException, CertificateEncodingException {
        ComboBox expBox = getComboBoxByFXID("expFormat");
        ComboBox typeBox = getComboBoxByFXID("keyStoreType");
        TextField passwd = getTextFieldByFXID("passwd");
        ComboBox aliases = getComboBoxByFXID("aliases");
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
                KeyStore store =  KeyStoreTool.initStore(storeType.getType(), passwd.getText());
                File outFile = showSaveDialogFromButton(event, "expTarget");
                targetStream = new FileOutputStream(outFile);
                String alias = actualCert.getSubjectDN().getName();
                KeyStoreTool.addCertificate(store, actualCert, alias);
                KeyStoreTool.storeKeyStore(store, targetStream, passwd.getText().toCharArray());
            }
        }

    }

    @FXML
    public void loadStore(ActionEvent event) throws Exception {
        TextField passwd = getTextFieldByFXID("passwd");
        ComboBox typeBox = getComboBoxByFXID("keyStoreType");
        ComboBox aliasBox = getComboBoxByFXID("aliases");
        KeyStoreTool.StoreType storeType = (KeyStoreTool.StoreType)
                typeBox.getSelectionModel().getSelectedItem();
        KeyStore store = KeyStoreTool.loadStore(new FileInputStream(storeFile),
                passwd.getText().toCharArray(),
                storeType.getType());
        Enumeration<String> aliases = store.aliases();
        while(aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            aliasBox.getItems().add(alias);
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
        storeFile = inFile
        ;
    }

    @FXML
    protected void goBack(ActionEvent event) throws IOException, CertificateEncodingException {
        SecHarry.setRoot("certificates", SecHarry.CSS.ABBY);
    }
}
