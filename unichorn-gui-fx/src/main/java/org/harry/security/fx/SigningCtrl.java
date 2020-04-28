package org.harry.security.fx;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TextField;
import org.harry.security.CMSSigner;
import org.harry.security.util.SigningUtil;
import org.harry.security.util.algoritms.CryptoAlg;
import org.harry.security.util.algoritms.DigestAlg;
import org.harry.security.util.algoritms.SignatureAlg;
import org.harry.security.util.bean.SigningBean;

import javax.activation.DataSource;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static org.harry.security.fx.util.Miscellaneous.getComboBoxByFXID;
import static org.harry.security.fx.util.Miscellaneous.getTextFieldByFXID;

public class SigningCtrl implements ControllerInit {


    List<String> tspURLS = Arrays.asList(
            "http://timestamp.globalsign.com/scripts/timstamp.dll",
    "https://timestamp.geotrust.com/tsa",
    "http://timestamp.comodoca.com/rfc3161",
    "http://timestamp.wosign.com",
    "http://tsa.startssl.com/rfc3161",
    "http://time.certum.pl",
    "http://timestamp.digicert.com",
    "https://freetsa.org",
    "http://dse200.ncipher.com/TSS/HttpTspServer",
    "http://tsa.safecreative.org",
    "http://zeitstempel.dfn.de",
    "https://ca.signfiles.com/tsa/get.aspx",
    "http://services.globaltrustfinder.com/adss/tsa",
    "https://tsp.iaik.tugraz.at/tsp/TspRequest",
    "http://timestamp.apple.com/ts01",
    "http://timestamp.entrust.net/TSS/RFC3161sha2TS"
    );
    File keyStoreStream = null;
    File dataInput = null;
    File outFile = null;




    @Override
    public Scene init() {
        ComboBox comboBox = getComboBoxByFXID("mode");

        comboBox.getItems().add(SigningBean.Mode.EXPLICIT);
        comboBox.getItems().add(SigningBean.Mode.IMPLICIT);

        ComboBox sigType = getComboBoxByFXID("sigType");
        sigType.getItems().addAll(SigningBean.SigningType.values());
        ComboBox sigBox = getComboBoxByFXID("sigAlg");
        sigBox.getItems().addAll(SignatureAlg.values());
        ComboBox digestBox = getComboBoxByFXID("digestAlg");
        digestBox.getItems().addAll(DigestAlg.values());
        ComboBox encrBox = getComboBoxByFXID("encrAlg");
        encrBox.getItems().addAll(CryptoAlg.values());
        ComboBox tsp = getComboBoxByFXID("tspField");
        tsp.getItems().addAll(tspURLS);
        return comboBox.getScene();
    }

    @FXML
    public void cancelSigning(ActionEvent event) throws IOException {
        SecHarry.setRoot("main");
    }

    @FXML
    public void signEncr(ActionEvent event) throws Exception {
        this.sign();
    }

    @FXML
    public void cadesParams(ActionEvent event) {

    }

    private void sign() throws IOException {

        SigningBean bean = SecHarry.contexts.get();
        bean = filloutBean(bean);
        SigningUtil util = SigningUtil.newBuilder()
                .withSignaturePath(bean.getOutputPath())
                .withMode(bean.getSigningMode().getMode())
                .build();
        if(bean.getAction().equals(CMSSigner.Commands.SIGN)) {
            if (bean.getSignatureType().equals(SigningBean.SigningType.CMS)) {
                DataSource outSrc = util.signCMS(bean);
                util.writeToFile(outSrc, bean);
            } else if (bean.getSignatureType().equals(SigningBean.SigningType.CAdES)) {
                DataSource outSrc = util.signCAdES(
                        bean, true);
                util.writeToFile(outSrc, bean);
            }
        } else if (bean.getAction().equals(CMSSigner.Commands.ENCRYPT_SIGN)) {
            DataSource outSrc = util.encryptAndSign(bean);
            util.writeToFile(outSrc, bean);
        }

    }

    private SigningBean filloutBean(SigningBean bean) {
        ComboBox sigType = getComboBoxByFXID("sigType");
        SigningBean.SigningType type = (SigningBean.SigningType) sigType.getSelectionModel().getSelectedItem();
        ComboBox sigAlg = getComboBoxByFXID("sigAlg");
        SignatureAlg signatureAlg = (SignatureAlg)sigAlg.getSelectionModel().getSelectedItem();
        ComboBox digestAlg = getComboBoxByFXID("digestAlg");
        DigestAlg digestAlgorithm = (DigestAlg)digestAlg.getSelectionModel().getSelectedItem();
        ComboBox encrAlg =  getComboBoxByFXID("encrAlg");
        CryptoAlg  encrAlgorithm = (CryptoAlg) encrAlg.getSelectionModel().getSelectedItem();
        ComboBox modeBox =  getComboBoxByFXID("mode");
        SigningBean.Mode mode = (SigningBean.Mode) modeBox.getSelectionModel().getSelectedItem();
        TextField passwdField =  getTextFieldByFXID("passwd");
        ComboBox tspField =  getComboBoxByFXID("tspField");
        String value = (String) tspField.getSelectionModel().getSelectedItem();
        bean.setSignatureAlgorithm(signatureAlg)
                .setSignatureType(type)
                .setDecryptPWD(passwdField.getText())
                .setDigestAlgorithm(digestAlgorithm)
                .setCryptoAlgorithm(encrAlgorithm)
                .setSigningMode(mode)
                .setTspURL(value);
        sigAlg.getSelectionModel().clearSelection();
        digestAlg.getSelectionModel().clearSelection();
        modeBox.getSelectionModel().clearSelection();
        encrAlg.getSelectionModel().clearSelection();
        tspField.getSelectionModel().clearSelection();
        return bean;
    }
}
