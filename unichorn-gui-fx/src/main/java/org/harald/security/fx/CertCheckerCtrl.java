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
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.web.WebView;
import org.harald.security.fx.util.Miscellaneous;
import org.harry.security.util.CertLoader;
import org.harry.security.util.HttpsChecker;
import org.harry.security.util.ServerInfoGetter;
import org.harry.security.util.Tuple;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;


public class CertCheckerCtrl implements ControllerInit {

    Map<String, X509Certificate> certMap = new HashMap<>();

    Map<String, X509Certificate> checkedCertMap = new HashMap<>();

    String oldColor = null;

    X509Certificate selectedCert;

    java.security.cert.X509Certificate[] actualCerts;

    public Scene init() {

        ListView listViewCheck = Miscellaneous.getListViewByFXID("certList");

        listViewCheck.getSelectionModel().selectedItemProperty().addListener(new ChangeListener() {
            @Override
            public void changed(ObservableValue observable, Object oldValue, Object newValue)  {
                TextArea text = Miscellaneous.getTextAreaByFXID("certArea");
                String newStringVal = (String)newValue;
                System.out.println("Selected item: " + newStringVal);
                BigInteger serial = new BigInteger(newStringVal);
                for (java.security.cert.X509Certificate cert: actualCerts) {
                    if (cert.getSerialNumber().equals(serial)) {
                        X509Certificate printable = null;
                        try {
                            printable = new X509Certificate(cert.getEncoded());
                        } catch (CertificateException e) {
                            e.printStackTrace();
                        }
                        text.setText(printable.toString(true));
                    }
                }
           }});
        return listViewCheck.getScene();
    }

    private String  dateAsString(Date notBefore) {
        DateFormat fmt = SimpleDateFormat.getDateInstance();
        String notBeforeString = fmt.format(notBefore);
        return notBeforeString;
    }



    @FXML
    private void checkTrust(ActionEvent event) throws Exception {
        TextField url = Miscellaneous.getTextFieldByFXID("httpURL");
        TextField port = Miscellaneous.getTextFieldByFXID("port");
        TextArea text = Miscellaneous.getTextAreaByFXID("certArea");
        TextArea web = Miscellaneous.getTextAreaByFXID("report");
        ObservableList styleList = url.getStyleClass();
        url.textProperty().addListener((observable, oldValue, newValue) -> {
            setColor(styleList, "custom-white");
        });
        CheckBox ocspCheck = Miscellaneous.getCheckBoxByFXID("ocspCheck");
        CheckBox altResponder = Miscellaneous.getCheckBoxByFXID("altResp");
        Writer writer = new StringWriter();
        ServerInfoGetter getter = new ServerInfoGetter(url.getText(), Integer.parseInt(port.getText()), writer, "");
        Hashtable<java.security.cert.X509Certificate, java.security.cert.X509Certificate[]> serverCerts = getter.showInfo();
        Enumeration<java.security.cert.X509Certificate[]> values = serverCerts.elements();
        if(values.hasMoreElements()) {
            java.security.cert.X509Certificate[] array = values.nextElement();
            ListView listView = Miscellaneous.getListViewByFXID("certList");
            listView.getItems().clear();
            actualCerts = array;
            for (java.security.cert.X509Certificate cert: array) {
                iaik.x509.X509Certificate printable = new iaik.x509.X509Certificate(cert.getEncoded());
                listView.getItems().add(printable.getSerialNumber().toString(10));
                text.setText(printable.toString(true));
                web.setText(writer.toString());
            }
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

