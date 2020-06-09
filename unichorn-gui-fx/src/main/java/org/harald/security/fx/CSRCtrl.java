package org.harald.security.fx;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.Name;
import iaik.pkcs.pkcs10.CertificateRequest;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.KeyUsage;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.CheckBox;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import org.harald.security.fx.util.Miscellaneous;
import org.harry.security.util.CertificateWizzard;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.CSRHandler;
import org.harry.security.util.certandkey.KeyStoreTool;

import java.io.*;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Enumeration;
import java.util.UUID;

import static org.harry.security.CommonConst.APP_DIR_WORKING;


public class CSRCtrl implements ControllerInit{


    @FXML private CheckBox keyAgreement;
    @FXML private CheckBox digitalSignature;
    @FXML private CheckBox nonRepudiation;
    @FXML private CheckBox keyEncipherment;
    @FXML private CheckBox dataEncipherment;
    @FXML private CheckBox keyCertSign;
    @FXML private CheckBox cRLSign;
    @FXML private CheckBox encipherOnly;
    @FXML private CheckBox decipherOnly;
    @FXML private CheckBox OCSPSigning;

    File p12Store;
    @Override
    public Scene init() {
        return null;
    }

    @FXML
    public void sendCSR(ActionEvent event) throws Exception {
        Name subject = createSubject();
        p12Store = Miscellaneous.showSaveDialogFromButton(event,null);
        CSRHandler.signCert(subject, p12Store.getAbsolutePath(), createKeyUsage(), OCSPSigning.isSelected());
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
    public void signLocal(ActionEvent event) throws Exception {
        Name subject = createSubject();
        p12Store = Miscellaneous.showSaveDialogFromButton(event,null);
        KeyPair kp = CertificateWizzard.generateKeyPair("RSA", 4096);
        InputStream certSignStream = CSRHandler.createCertificateRequestStream(subject, kp,"geheim",
                createKeyUsage(), OCSPSigning.isSelected());
        FileOutputStream outPW = new FileOutputStream(new File(APP_DIR_WORKING, "geheim"));
        outPW.write("geheim".getBytes());
        outPW.flush();
        outPW.close();
        CertificateRequest certReq = new CertificateRequest(certSignStream);
        KeyStore store = KeyStoreTool.initStore("PKCS12", "changeit");
        Tuple<PrivateKey, X509Certificate[]> result = CSRHandler.certSigning(certReq, kp.getPrivate());
        KeyStoreTool.addKey(store, result.getFirst(),
                "changeit".toCharArray(), result.getSecond(), UUID.randomUUID().toString());
        OutputStream out = new FileOutputStream(p12Store);
        KeyStoreTool.storeKeyStore(store, out, "changeit".toCharArray());
        out.flush();
        out.close();
        TextArea area = Miscellaneous.getTextAreaByFXID("cert_descr");
        area.setText(result.getSecond()[0].toString(true));
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

    KeyUsage createKeyUsage() {
        int usage = 0;
        if (keyAgreement.isSelected()) {
            usage |= KeyUsage.keyAgreement;
        }
        if(digitalSignature.isSelected()) {
            usage |= KeyUsage.digitalSignature;
        }
        if(nonRepudiation.isSelected()) {
            usage |= KeyUsage.nonRepudiation;
        }
        if (keyEncipherment.isSelected()) {
            usage |= KeyUsage.keyEncipherment;
        }
        if (dataEncipherment.isSelected()) {
            usage |= KeyUsage.dataEncipherment;
        }
        if (keyCertSign.isSelected()) {
            usage |= KeyUsage.keyCertSign;
        }
        if (cRLSign.isSelected()) {
            usage |= KeyUsage.cRLSign;
        }
        if (encipherOnly.isSelected()) {
            usage |= KeyUsage.encipherOnly;
        }
        if (decipherOnly.isSelected()) {
            usage |= KeyUsage.decipherOnly;
        }
        return new KeyUsage(usage);
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
