package org.harry.security.fx;

import iaik.x509.X509Certificate;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TextArea;
import org.harry.security.util.trustlist.CertWriterReader;

import java.io.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.UUID;

import static org.harry.security.fx.util.Miscellaneous.*;

public class CertActionCtrl implements ControllerInit {

    private X509Certificate actualCert = null;

    private InputStream sourceStream = null;

    private OutputStream targetStream = null;

    @Override
    public Scene init() {
        ComboBox impBox = getComboBoxByFXID("impFormat");
        impBox.getItems().addAll(CertWriterReader.CertType.values());
        ComboBox expBox = getComboBoxByFXID("expFormat");
        expBox.getItems().addAll(CertWriterReader.CertType.values());
        return expBox.getScene();
    }

    @FXML
    protected void importCert(ActionEvent event) throws IOException, CertificateException {
        ComboBox impBox = getComboBoxByFXID("impFormat");
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


        }
    }

    @FXML
    protected void exportCert(ActionEvent event) throws IOException, CertificateEncodingException {
        ComboBox expBox = getComboBoxByFXID("expFormat");
        if (actualCert !=null && targetStream !=null) {
            CertWriterReader.CertType certType = (CertWriterReader.CertType)
                    expBox.getSelectionModel().getSelectedItem();
            if (certType.equals(CertWriterReader.CertType.PEM)) {
                CertWriterReader reader = new CertWriterReader(actualCert);
                reader.writeToFilePEM(targetStream);
            }else if (certType.equals(CertWriterReader.CertType.X509)) {
                CertWriterReader reader = new CertWriterReader(actualCert);
                reader.writeX509(targetStream);
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
    protected void goBack(ActionEvent event) throws IOException, CertificateEncodingException {
        SecHarry.setRoot("certificates");
    }
}
