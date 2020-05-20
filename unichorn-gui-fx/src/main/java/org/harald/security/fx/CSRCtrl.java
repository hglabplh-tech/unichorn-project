package org.harald.security.fx;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.Name;
import iaik.x509.X509Certificate;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import org.harald.security.fx.util.Miscellaneous;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.CSRHandler;
import org.harry.security.util.certandkey.KeyStoreTool;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Enumeration;


public class CSRCtrl implements ControllerInit{

    File p12Store;
    @Override
    public Scene init() {
        return null;
    }

    @FXML
    public void sendCSR(ActionEvent event) throws Exception {
        Name subject = createSubject();
        p12Store = Miscellaneous.showSaveDialogFromButton(event,null);
        CSRHandler.signCert(subject, p12Store.getAbsolutePath());
        KeyStore store = KeyStoreTool.loadStore(new FileInputStream(p12Store),
                "changeit".toCharArray(), "PKCS12");
        Enumeration<String> aliases = store.aliases();
        String alias = aliases.nextElement();
        Tuple<PrivateKey, X509Certificate[]> tuple = KeyStoreTool.getKeyEntry(store,
                alias, "changeit".toCharArray());
        TextArea area = Miscellaneous.getTextAreaByFXID("cert_descr");
        area.setText(tuple.getSecond()[0].toString(true));
    }

    @FXML
    public void setSigning(ActionEvent event) throws Exception  {
        if (p12Store != null) {
            CSRHandler.setSigningCert(p12Store);
        }
    }


    @FXML
    public void back(ActionEvent event) throws IOException  {
        SecHarry.setRoot("certificates", SecHarry.CSS.UNICHORN);
    }

    Name createSubject() {

        TextField common = Miscellaneous.getTextFieldByFXID("common");                ;
        TextField country = Miscellaneous.getTextFieldByFXID("country");
        TextField org= Miscellaneous.getTextFieldByFXID("org");
        TextField orgunit = Miscellaneous.getTextFieldByFXID("orgunit");
        TextField locality = Miscellaneous.getTextFieldByFXID("locality");
        // create a new Name
        Name subject = new Name();
        subject.addRDN(ObjectID.country, country.getText());
        subject.addRDN(ObjectID.locality, locality.getText());
        subject.addRDN(ObjectID.organization, org.getText());
        subject.addRDN(ObjectID.organizationalUnit, orgunit.getText());
        subject.addRDN(ObjectID.commonName, common.getText());
        return subject;
    }
}
