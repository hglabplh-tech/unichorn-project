package org.harald.security.fx;

import iaik.utils.Util;
import iaik.x509.attr.AttributeCertificate;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TextField;
import org.harry.security.CMSSigner;
import org.harry.security.pkcs11.CardSigner;
import org.harry.security.util.ConfigReader;
import org.harry.security.util.SigningUtil;
import org.harry.security.util.Tuple;
import org.harry.security.util.algoritms.CryptoAlg;
import org.harry.security.util.algoritms.DigestAlg;
import org.harry.security.util.algoritms.SignatureAlg;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.GSON;
import org.harry.security.util.httpclient.HttpClientConnection;

import javax.activation.DataSource;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;

import static org.harald.security.fx.util.Miscellaneous.*;
import static org.harry.security.CommonConst.TSP_URL;

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
    "http://timestamp.entrust.net/TSS/RFC3161sha2TS",
    TSP_URL

    );
    File keyStoreStream = null;
    File dataInput = null;
    File outFile = null;
    AttributeCertificate attributeCertificate;




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
        SecHarry.setRoot("main", SecHarry.CSS.ABBY);
    }

    @FXML
    public void certSel(ActionEvent event) throws IOException, CertificateException {
        File attrCertFile = showOpenDialog(event, "attrCert");
        attributeCertificate = new AttributeCertificate(new FileInputStream(attrCertFile));
    }

    @FXML
    public void signEncr(ActionEvent event) throws Exception {
        this.sign();
    }

    @FXML
    public void cadesParams(ActionEvent event) {

    }

    private void sign() throws Exception {
        CheckBox archiveInfo = getCheckBoxByFXID("archiveInfo");
        CheckBox cardSigning = getCheckBoxByFXID("cardsigning");
        boolean addArchiveInfo = archiveInfo.isSelected();
        SigningBean bean = SecHarry.contexts.get();
        bean = filloutBean(bean);
        SigningUtil util = new SigningUtil();
        if(bean.getAction().equals(CMSSigner.Commands.SIGN)) {
            if (cardSigning.isSelected()) {
                String cardPin = getSmartCardPIN();
                boolean reallySign = (cardPin != null && cardPin.length() == 6);
                CardSigner signer = new CardSigner();
                signer.readCardData();
                if (reallySign) {
                    signer.getKeyStore(cardPin);
                    DataSource signed = signer.sign(bean, addArchiveInfo, bean.getWalker());
                    util.writeToFile(signed, bean);
                }
            } else if (!cardSigning.isSelected()){
                GSON.Params params = new GSON.Params();
                GSON.Signing signing = new GSON.Signing();
                params.signing = signing;
                params.parmType = "docSign";
                params.signing.signatureType = bean.getSignatureType().name();
                params.signing.mode = bean.getSigningMode().getMode();
                if (bean.getSignatureAlgorithm() != null) {
                    params.signing.signatureAlgorithm = bean.getSignatureAlgorithm().getName();
                }
                if (bean.getDigestAlgorithm() != null) {
                    params.signing.digestAlgorithm = bean.getDigestAlgorithm().getName();
                    if (attributeCertificate != null) {
                        params.signing.attributeCert = Util.toBase64String(attributeCertificate.getEncoded());
                    }
                }
                if (bean.getSignatureType().equals(SigningBean.SigningType.CAdES)) {
                    GSON.SigningCAdES cades = new GSON.SigningCAdES();
                    params.signing.cadesParams = cades;
                    params.signing.cadesParams.TSAURL = bean.getTspURL();
                    params.signing.cadesParams.addArchiveinfo = addArchiveInfo;
                }
                HttpClientConnection
                        .sendDocSigningRequest(bean.getDataIN(),
                                params, new File(bean.getOutputPath()));

            } else if (bean.getAction().equals(CMSSigner.Commands.ENCRYPT_SIGN)) {
                Tuple<DataSource, DataSource> outCome = util.encryptAndSign(bean);
                util.writeToFile(outCome.getSecond(), bean);
            }
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

    private String getSmartCardPIN() {
        TextField pin = getTextFieldByFXID("pin");
        String pkcs11Pin = System.getenv("PKCS11PIN");
        ConfigReader.MainProperties props = ConfigReader.loadStore();
        String cardPIN;
        if (pkcs11Pin != null) {
            cardPIN = pkcs11Pin;
        } else if (props.getPkcs11Pin() != null && !props.getPkcs11Pin().isEmpty()) {
            cardPIN = props.getPkcs11Pin();
        } else {
            cardPIN = pin.getText();
        }
        return cardPIN.trim();
    }
}
