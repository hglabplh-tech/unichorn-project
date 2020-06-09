package org.harald.security.fx;

import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.x509.X509Certificate;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.ListView;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextArea;
import org.harry.security.pkcs11.CardManager;

import java.util.List;
import java.util.Optional;

public class CardManagerCtrl implements ControllerInit {

    @FXML
    private PasswordField pinField;

    @FXML
    private ListView<String> certificates;

    @FXML
    private ListView<String> publicKey;

    @FXML
    private ListView<String> privateKey;

    @FXML
    private TextArea content;

    private List<PublicKey> publicKeyList;

    private List<PrivateKey> privateKeyList;

    private List<X509Certificate> certificateList;

    @Override
    public Scene init() {
        return null;
    }

    @FXML
    public void cardLoad(ActionEvent event) throws Exception {
        CardManager manager = new CardManager();
        if (pinField.getText() != null && pinField.getText().length() >= 4) {
            manager.readCardData(pinField.getText());
            publicKeyList = manager.getPublicKeys();

            privateKeyList = manager.getPrivateKeys();
            this.certificateList = manager.getCertificates();
            for (PrivateKey key: privateKeyList){
                privateKey.getItems().add(Long.toString(key.getObjectHandle()));
            }

            for (PublicKey key: publicKeyList){
                publicKey.getItems().add(Long.toString(key.getObjectHandle()));
            }


            for (X509Certificate certificate: this.certificateList){
                certificates.getItems().add(certificate.getSubjectDN().getName());
            }

        }
        publicKey.getSelectionModel().selectedItemProperty().addListener(new ChangeListener() {
            @Override
            public void changed(ObservableValue observable, Object oldValue, Object newValue) {
                String newStringVal = (String)newValue;
                long objectId = Long.parseLong(newStringVal);
                Optional<PublicKey> actualKey = publicKeyList.stream()
                        .filter(e -> e.getObjectHandle() == objectId)
                        .findFirst();
                if (actualKey.isPresent()) {
                    System.out.println("Selected item: " + newStringVal);
                    content.setText(actualKey.get().toString());
                }
            }
        });

        privateKey.getSelectionModel().selectedItemProperty().addListener(new ChangeListener() {
            @Override
            public void changed(ObservableValue observable, Object oldValue, Object newValue) {
                String newStringVal = (String)newValue;
                long objectId = Long.parseLong(newStringVal);
                Optional<PrivateKey> actualKey = privateKeyList.stream()
                        .filter(e -> e.getObjectHandle() == objectId)
                        .findFirst();
                if (actualKey.isPresent()) {
                    System.out.println("Selected item: " + newStringVal);
                    content.setText(actualKey.get().toString());
                }
            }
        });

        certificates.getSelectionModel().selectedItemProperty().addListener(new ChangeListener() {
            @Override
            public void changed(ObservableValue observable, Object oldValue, Object newValue) {
                String newStringVal = (String)newValue;
                Optional<X509Certificate> actualCert = certificateList.stream()
                        .filter(e -> e.getSubjectDN().getName().equals(newStringVal))
                        .findFirst();
                if (actualCert.isPresent()) {
                    System.out.println("Selected item: " + newStringVal);
                    content.setText(actualCert.get().toString(true));
                }
            }
        });


    }
}
