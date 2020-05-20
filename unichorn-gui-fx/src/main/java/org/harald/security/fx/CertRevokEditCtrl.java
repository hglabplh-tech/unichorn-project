package org.harald.security.fx;

import iaik.x509.X509Certificate;
import iaik.x509.X509ExtensionException;
import iaik.x509.extensions.ReasonCode;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TextField;
import org.harald.security.fx.util.Miscellaneous;
import org.harald.security.fx.util.TextListCell;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.CSRHandler;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.crlext.CRLEdit;
import org.harry.security.util.httpclient.HttpClientConnection;

import java.io.*;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class CertRevokEditCtrl implements ControllerInit {

    private File keystore;
    private File editTemp;
    private CRLEdit editCRL;
    private List<ReasonCode> addedCodes = new ArrayList<>();
    private List<ReasonCode> revokedCodes = new ArrayList<>();
    @Override
    public Scene init() {
        ListView source = Miscellaneous.getListViewByFXID("source");
        ListView added = Miscellaneous.getListViewByFXID("added");
        ListView revoked = Miscellaneous.getListViewByFXID("revoked");
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
        Label status = Miscellaneous.getLabelByFXID("status");
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
        Label status = Miscellaneous.getLabelByFXID("status");
        KeyStore appStore = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(appStore);
        X509Certificate issuer = keys.getSecond()[0];
        editCRL = new CRLEdit(issuer.getSubjectDN());
        status.setText("CRL generated");
        return;
    }

    public void reasonCode(ActionEvent event) {
        ListView added = Miscellaneous.getListViewByFXID("added");
        added.getItems().size();
        ObservableList<Integer> indices = added.getSelectionModel().getSelectedIndices();
        addedCodes.add(indices.get(0), new ReasonCode(ReasonCode.keyCompromise));
    }

    public void revokedCode(ActionEvent event) {
        ListView revoked = Miscellaneous.getListViewByFXID("revoked");
        revoked.getItems().size();
        ObservableList<Integer> indices = revoked.getSelectionModel().getSelectedIndices();
        /* TODO have to look for real selection
        */
        revokedCodes.add(indices.get(0), new ReasonCode(ReasonCode.removeFromCRL));
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
        CSRHandler.resignCRL();
    }

    private void changeTheValues() throws IOException, X509ExtensionException {
        ListView added = Miscellaneous.getListViewByFXID("added");
        ListView revoked = Miscellaneous.getListViewByFXID("revoked");
        TextField passwd = Miscellaneous.getTextFieldByFXID("password");
        KeyStore store = KeyStoreTool.loadStore(new FileInputStream(keystore),passwd.getText().toCharArray(), "PKCS12");

        int index = 0;
        for (Object alias: added.getItems()) {
            if (!((String)alias).isEmpty()) {
                ReasonCode code = addedCodes.get(index);
                X509Certificate cert = KeyStoreTool.getCertificateEntry(store, (String) alias);
                editCRL.addCertificate(cert, code);
                index++;
            }
        }


        index = 0;
        for (Object alias: revoked.getItems()) {
            if (!((String)alias).isEmpty()) {
                ReasonCode code = revokedCodes.get(index);
                X509Certificate cert = KeyStoreTool.getCertificateEntry(store, (String) alias);
                editCRL.addRevokedCertificate(cert, code);
                index++;
            }
        }
    }

    @FXML
    public void open(ActionEvent event) throws IOException, KeyStoreException {
        TextField passwd = Miscellaneous.getTextFieldByFXID("password");
        ListView source = Miscellaneous.getListViewByFXID("source");
        KeyStore store = KeyStoreTool.loadStore(new FileInputStream(keystore),passwd.getText().toCharArray(), "PKCS12");
        Enumeration<String> aliases = store.aliases();
        while(aliases.hasMoreElements()) {
            source.getItems().add(aliases.nextElement());
        }

    }

    @FXML
    public void select(ActionEvent event) {
        keystore = Miscellaneous.showOpenDialog(event, "location");
    }


}
