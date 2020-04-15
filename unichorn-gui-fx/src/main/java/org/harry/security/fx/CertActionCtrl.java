package org.harry.security.fx;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;

public class CertActionCtrl implements ControllerInit {



    @Override
    public Scene init() {
        return null;
    }

    @FXML
    protected void importCert(ActionEvent event) throws IOException, CertificateEncodingException {

    }

    @FXML
    protected void exportCert(ActionEvent event) throws IOException, CertificateEncodingException {

    }
}
