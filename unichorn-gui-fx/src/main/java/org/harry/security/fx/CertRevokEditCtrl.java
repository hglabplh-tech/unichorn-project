package org.harry.security.fx;

import iaik.x509.X509Certificate;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TextField;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.harry.security.fx.util.TextListCell;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.crlext.CRLEdit;
import org.harry.security.util.httpclient.HttpClientConnection;

import java.io.*;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.util.Enumeration;

import static org.harry.security.fx.util.Miscellaneous.*;

public class CertRevokEditCtrl implements ControllerInit {

    private File keystore;
    private File editTemp;
    private CRLEdit editCRL;
    @Override
    public Scene init() {
        ListView source = getListViewByFXID("source");
        ListView added = getListViewByFXID("added");
        ListView revoked = getListViewByFXID("revoked");
        source.setCellFactory(param -> new TextListCell.TextCell());
        source.getItems().add("");
        added.setCellFactory(param -> new TextListCell.TextCell());
        added.getItems().add("");
        revoked.setCellFactory(param -> new TextListCell.TextCell());
        revoked.getItems().add("");

        return null;
    }

    @FXML
    public void download(ActionEvent event) throws IOException {
        editTemp = File.createTempFile("edit", ".crl");
        URL connectUrl = new URL("http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/ocsp");
        InputStream response = HttpClientConnection
                .sendGetForResources(connectUrl, "crl", new FileOutputStream(editTemp));
        Label status = getLabelByFXID("status");
        if (response != null) {
            editCRL = new CRLEdit(response);
            response.close();
            status.setText("CRL downloaded temp:" + editTemp.getName());
            return;
        }
        status.setText("CRL downloaded failed " + editTemp.getName());
    }

    @FXML
    public void freshCRL(ActionEvent event) throws IOException {
        editTemp = File.createTempFile("edit", ".crl");
        Label status = getLabelByFXID("status");
        KeyStore appStore = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(appStore);
        X509Certificate issuer = keys.getSecond()[0];
        editCRL = new CRLEdit(issuer.getSubjectDN());
        status.setText("CRL generated");
        return;
    }

    @FXML
    public void back(ActionEvent event) throws Exception {
        SecHarry.setRoot("main", SecHarry.CSS.UNICHORN);
    }

    @FXML
    public void upload(ActionEvent event) throws Exception {
        KeyStore appStore = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(appStore);
        changeTheValues();
        editCRL.signCRL(keys.getSecond()[0], keys.getFirst());
        editCRL.storeCRL(new FileOutputStream(editTemp));
        FileInputStream input = new FileInputStream(editTemp);
        HttpClientConnection.sendPutData(input, "crl");
    }

    private void changeTheValues() throws IOException {
        ListView added = getListViewByFXID("added");
        ListView revoked = getListViewByFXID("revoked");
        TextField passwd = getTextFieldByFXID("password");
        KeyStore store = KeyStoreTool.loadStore(new FileInputStream(keystore),passwd.getText().toCharArray(), "JKS");

        for (Object alias: added.getItems()) {
            if (!((String)alias).isEmpty()) {
                X509Certificate cert = KeyStoreTool.getCertificateEntry(store, (String) alias);
                editCRL.addCertificate(cert);
            }
        }


        for (Object alias: revoked.getItems()) {
            if (!((String)alias).isEmpty()) {
                X509Certificate cert = KeyStoreTool.getCertificateEntry(store, (String) alias);
                editCRL.addRevokedCertificate(cert);
            }
        }
    }

    @FXML
    public void open(ActionEvent event) throws IOException, KeyStoreException {
        TextField passwd = getTextFieldByFXID("password");
        ListView source = getListViewByFXID("source");
        KeyStore store = KeyStoreTool.loadStore(new FileInputStream(keystore),passwd.getText().toCharArray(), "JKS");
        Enumeration<String> aliases = store.aliases();
        while(aliases.hasMoreElements()) {
            source.getItems().add(aliases.nextElement());
        }

    }

    @FXML
    public void select(ActionEvent event) {
        keystore = showOpenDialog(event, "location");
    }


}
