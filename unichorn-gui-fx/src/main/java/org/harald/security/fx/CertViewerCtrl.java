package org.harald.security.fx;


import iaik.x509.X509Certificate;
import iaik.x509.ocsp.OCSPResponse;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ListView;
import javafx.scene.control.TextField;
import org.harald.security.fx.util.Miscellaneous;
import org.harry.security.util.CertLoader;
import org.harry.security.util.HttpsChecker;
import org.harry.security.util.Tuple;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;


public class CertViewerCtrl implements ControllerInit {

    Map<String, X509Certificate> certMap = new HashMap<>();

    Map<String, X509Certificate> checkedCertMap = new HashMap<>();

    String oldColor = null;

    X509Certificate selectedCert;

    public Scene init() {
        certMap = CertLoader.loadCertificatesFromWIN();
        ListView listView = Miscellaneous.getListViewByFXID("certList");
        listView.getItems().addAll(certMap.keySet());
        listView.getSelectionModel().selectedItemProperty().addListener(new ChangeListener() {
            @Override
            public void changed(ObservableValue observable, Object oldValue, Object newValue) {
                String newStringVal = (String)newValue;
                System.out.println("Selected item: " + newStringVal);
                selectedCert = certMap.get(newStringVal);
                if (selectedCert != null) {
                    X509Certificate iaikCert = selectedCert;
                    fillOutCertForm(iaikCert);
                }

            }
        });
        ListView listViewCheck = Miscellaneous.getListViewByFXID("checkedCerts");

        listViewCheck.getSelectionModel().selectedItemProperty().addListener(new ChangeListener() {
            @Override
            public void changed(ObservableValue observable, Object oldValue, Object newValue) {
                String newStringVal = (String)newValue;
                System.out.println("Selected item: " + newStringVal);
                selectedCert = checkedCertMap.get(newStringVal);
                if (selectedCert != null) {
                    fillOutCertForm(selectedCert);
                }
           }});
        return listViewCheck.getScene();
    }

    private void fillOutCertForm(X509Certificate iaikCert) {
        Principal issuer = iaikCert.getIssuerDN();
        Principal subject = iaikCert.getSubjectDN();
        String issuerName = issuer.getName();
        String subjectName = subject.getName();
        String serial = iaikCert.getSerialNumber().toString(10);
        String sigAlgName = "";
        try {
            sigAlgName = iaikCert.getSignatureAlgorithm().getJcaStandardName();
        } catch (NoSuchAlgorithmException e) {

        }
        String pubKeyAlg = iaikCert.getPublicKey().getAlgorithm();
        Date notBefore = iaikCert.getNotBefore();
        String notBeforeString = dateAsString(notBefore);
        Date notAfter = iaikCert.getNotAfter();
        String notAfterString = dateAsString(notAfter);
        byte [] fingerprint = iaikCert.getFingerprint();
        String fingerPrintStr = Miscellaneous.bytesToHex(fingerprint);
        String keyUsage = keyUsageToString(iaikCert.getKeyUsage());
        TextField serialField = Miscellaneous.getTextFieldByFXID("serial");
        serialField.commitValue();
        TextField subjectField = Miscellaneous.getTextFieldByFXID("owner");
        TextField issuerField = Miscellaneous.getTextFieldByFXID("issuer");
        TextField sigAlgField = Miscellaneous.getTextFieldByFXID("sigAlg");
        TextField pubKeyAlgField = Miscellaneous.getTextFieldByFXID("pubKeyAlg");
        TextField notBeforeField = Miscellaneous.getTextFieldByFXID("startDate");
        TextField notAfterField = Miscellaneous.getTextFieldByFXID("endDate");
        TextField fingerprintField = Miscellaneous.getTextFieldByFXID("fingerprint");
        TextField keyUsageField = Miscellaneous.getTextFieldByFXID("usage");
        subjectField.setText(subjectName);
        issuerField.setText(issuerName);
        serialField.setText(serial);
        sigAlgField.setText(sigAlgName);
        pubKeyAlgField.setText(pubKeyAlg);
        pubKeyAlgField.commitValue();
        notBeforeField.setText(notBeforeString);
        notAfterField.setText(notAfterString);
        fingerprintField.setText(fingerPrintStr);
        keyUsageField.setText(keyUsage);
    }

    String keyUsageToString(boolean[] usage) {
        StringBuffer buffer = new StringBuffer();
        if (usage != null) {
            if (usage[0]) {
                buffer.append("digitalSignature | ");
            }
            if (usage[1]) {
                buffer.append("nonRepudiation | ");
            }
            if (usage[2]) {
                buffer.append("keyEncipherment | ");
            }
            if (usage[3]) {
                buffer.append("dataEncipherment | ");
            }
            if (usage[4]) {
                buffer.append("keyAgreement | ");
            }
            if (usage[5]) {
                buffer.append("keyCertSign | ");
            }
            if (usage[6]) {
                buffer.append("cRLSign | ");
            }
            if (usage[7]) {
                buffer.append("encipherOnly | ");
            }
            if (usage[8]) {
                buffer.append("decipherOnly");
            }
        }
        return buffer.toString();
    }

    private String  dateAsString(Date notBefore) {
        DateFormat fmt = SimpleDateFormat.getDateInstance();
        String notBeforeString = fmt.format(notBefore);
        return notBeforeString;
    }

    @FXML
    private void checkTrust(ActionEvent event) throws IOException {
        TextField url = Miscellaneous.getTextFieldByFXID("httpURL");
        ObservableList styleList = url.getStyleClass();
        url.textProperty().addListener((observable, oldValue, newValue) -> {
            setColor(styleList, "custom-white");
        });
        CheckBox ocspCheck = Miscellaneous.getCheckBoxByFXID("ocspCheck");
        CheckBox altResponder = Miscellaneous.getCheckBoxByFXID("altResp");
        Tuple<Integer, List<X509Certificate>> certResp =
                HttpsChecker.checkHttpsCertValidity(url.getText(), ocspCheck.isSelected(),
                        altResponder.isSelected());


        if (certResp.getFirst() == OCSPResponse.successful) {
            setColor(styleList, "custom-green");
        } else if (certResp.getFirst() == OCSPResponse.tryLater) {
            setColor(styleList, "custom-yellow");
        } else if (certResp.getFirst() != OCSPResponse.successful){
            setColor(styleList, "custom-red");
        }
        checkedCertMap.clear();
        if (certResp.getSecond().size() > 0) {
            for (X509Certificate cert: certResp.getSecond()) {
                String key = HttpsChecker.extractCNFromCert(cert);
                checkedCertMap.put(key, cert);
            }
            ListView listView = Miscellaneous.getListViewByFXID("checkedCerts");
            listView.getItems().clear();
            listView.getItems().addAll(checkedCertMap.keySet());
        }
    }

    public void sendCSR(ActionEvent event) throws IOException {
        SecHarry.setRoot("sendcsr", SecHarry.CSS.UNICHORN);
    }

    @FXML
    protected void goBack(ActionEvent event) throws IOException {
        SecHarry.setRoot("main", SecHarry.CSS.ABBY);
    }

    @FXML
    protected void storeCertDialog(ActionEvent event) throws IOException, CertificateEncodingException {
       SecHarry.setRoot("certStore", SecHarry.CSS.UNICHORN);
    }

    private void setColor(ObservableList list, String color) {
        list.remove(oldColor);
        list.add(color);
        oldColor = color;
    }



}

