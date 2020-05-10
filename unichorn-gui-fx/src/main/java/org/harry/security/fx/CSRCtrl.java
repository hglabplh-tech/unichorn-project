package org.harry.security.fx;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.Name;
import iaik.x509.X509Certificate;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.CSRHandler;
import org.harry.security.util.certandkey.KeyStoreTool;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Enumeration;

import static org.harry.security.fx.util.Miscellaneous.getTextAreaByFXID;
import static org.harry.security.fx.util.Miscellaneous.getTextFieldByFXID;


public class CSRCtrl implements ControllerInit{
    @Override
    public Scene init() {
        return null;
    }

    @FXML
    public void sendCSR(ActionEvent event) throws Exception {
        Name subject = createSubject();
        File p12Temp = File.createTempFile("newCert", ".p12");
        CSRHandler.signCert(subject, p12Temp.getAbsolutePath());
        KeyStore store = KeyStoreTool.loadStore(new FileInputStream(p12Temp),
                "changeit".toCharArray(), "PKCS12");
        Enumeration<String> aliases = store.aliases();
        String alias = aliases.nextElement();
        Tuple<PrivateKey, X509Certificate[]> tuple = KeyStoreTool.getKeyEntry(store,
                alias, "changeit".toCharArray());
        TextArea area = getTextAreaByFXID("cert_descr");
        area.setText(tuple.getSecond()[0].toString(true));
    }

    @FXML
    public void back(ActionEvent event) throws IOException  {
        SecHarry.setRoot("certificates", SecHarry.CSS.UNICHORN);
    }

    Name createSubject() {

        TextField common = getTextFieldByFXID("common");                ;
        TextField country = getTextFieldByFXID("country");
        TextField org= getTextFieldByFXID("org");
        TextField orgunit = getTextFieldByFXID("orgunit");
        TextField locality = getTextFieldByFXID("locality");
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
