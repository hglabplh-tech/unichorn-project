package org.harald.security.fx;

import iaik.x509.X509Certificate;
import iaik.x509.attr.AttributeCertificate;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TextField;
import org.harry.security.util.SignXAdESUtil;
import org.harry.security.util.Tuple;
import org.harry.security.util.algoritms.XAdESDigestAlg;
import org.harry.security.util.algoritms.XAdESSigAlg;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.KeyStoreTool;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Enumeration;

import static org.harald.security.fx.util.Miscellaneous.showOpenDialog;
import static org.harald.security.fx.util.Miscellaneous.showSaveDialog;

public class SingningXAdESCtrl implements ControllerInit {

    @FXML TextField password;
    @FXML TextField keystoreLoc;
    @FXML TextField inputXML;
    @FXML ComboBox<String> aliases;
    @FXML TextField outputPath;
    @FXML TextField attrCert;
    @FXML ComboBox<XAdESDigestAlg> digestAlg;
    @FXML ComboBox<XAdESSigAlg> sigAlg;


    File keytoreFile = null;

    File inputFile = null;

    File outputFile = null;

    File attrCertFile = null;

    private SigningBean signingBean;


    @Override
    public Scene init() {
        signingBean = SecHarry.contexts.get();
        sigAlg.getItems().addAll(XAdESSigAlg.values());
        digestAlg.getItems().addAll(XAdESDigestAlg.values());
        return null;
    }

    @FXML
    public void selectStoreLoc(ActionEvent event) {
        keytoreFile = showOpenDialog(event, keystoreLoc);
    }

    @FXML
    public void loadStore(ActionEvent event) throws Exception  {
        KeyStore store = KeyStoreTool.loadStore(new FileInputStream(keytoreFile),
                password.getText().toCharArray(),
                "PKCS12");
        Enumeration<String> aliases = store.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            this.aliases.getItems().add(alias);
        }
    }

    @FXML
    public void selInputXML(ActionEvent event) {
        inputFile = showOpenDialog(event, inputXML);
    }

    @FXML
    public void selOutput(ActionEvent event) {
        outputFile = showSaveDialog(event, outputPath);
    }

    @FXML
    public void selectAttrCert(ActionEvent event) {
        attrCertFile = showOpenDialog(event, attrCert);
    }

    @FXML
    public void sign(ActionEvent event) throws Exception {
        String alias = (String)this.aliases.getSelectionModel().getSelectedItem();
        if (inputFile != null && alias != null && outputFile != null &&
                keytoreFile != null && password.getText() != null) {
            XAdESDigestAlg dAlg = digestAlg.getSelectionModel().getSelectedItem();
            XAdESSigAlg sAlg = sigAlg.getSelectionModel().getSelectedItem();
            KeyStore store = KeyStoreTool.loadStore(new FileInputStream(keytoreFile),
                    password.getText().toCharArray(), "PKCS12");
            Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getKeyEntry(store, alias,
                    password.getText().toCharArray());
            SignXAdESUtil util = new SignXAdESUtil(keys.getFirst(),
                    keys.getSecond());
            SignXAdESUtil.XAdESParams params = util.newParams();
            if (dAlg != null) {
                params.setDigestAlg(dAlg.getConstantName());
            }
            if (sAlg != null) {
                params.setDigestAlg(sAlg.getConstantName());
            }
            if (attrCertFile != null) {
                AttributeCertificate attrCert = new AttributeCertificate(new FileInputStream(attrCertFile));
                params.setSignerRole(attrCert);
            }
            util.prepareSigning(new FileInputStream(inputFile), params );
            OutputStream stream = new FileOutputStream(outputFile);
            util.sign(stream);
        }
    }

    @FXML
    public void back(ActionEvent event) throws IOException {
        SecHarry.setRoot("main", SecHarry.CSS.UNICHORN);
    }
}
