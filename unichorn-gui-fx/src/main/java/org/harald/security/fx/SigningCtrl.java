package org.harald.security.fx;

import iaik.pdf.parameters.PadesBESParameters;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.attr.AttributeCertificate;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TextField;
import org.harry.security.CMSSigner;
import org.harry.security.pkcs11.CardManager;
import org.harry.security.util.ConfigReader;
import org.harry.security.util.SignPDFUtil;
import org.harry.security.util.SigningUtil;
import org.harry.security.util.Tuple;
import org.harry.security.util.algoritms.CryptoAlg;
import org.harry.security.util.algoritms.DigestAlg;
import org.harry.security.util.algoritms.SignatureAlg;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.certandkey.GSON;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.httpclient.HttpClientConnection;

import javax.activation.DataSource;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Enumeration;
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
    TSP_URL);

    @FXML TextField pin;
    @FXML ComboBox aliasBox;
    @FXML CheckBox signLoacal;


    File keyStoreFile = null;
    KeyStore store;
    File dataInput = null;
    File outFile = null;
    AttributeCertificate attributeCertificate;
    SigningBean signingBean = SecHarry.contexts.get();
    File keystoreFile;




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
        signingBean = SecHarry.contexts.get();
        String alias = (String)aliasBox.getSelectionModel().getSelectedItem();
        if (!cardSigning.isSelected()) {
            Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getKeyEntry(store, alias, pin.getText().toCharArray());
            CertWriterReader.KeyStoreBean keyStoreBean = new CertWriterReader.KeyStoreBean(keys.getSecond(), keys.getFirst());
            signingBean.setKeyStoreBean(keyStoreBean);
        }
        signingBean = filloutBean(signingBean);
        SigningUtil util = new SigningUtil();
        if(signingBean.getAction().equals(CMSSigner.Commands.SIGN)) {
            if (cardSigning.isSelected()) {
                String cardPin = getSmartCardPIN();
                boolean reallySign = (cardPin != null && cardPin.length() == 6);
                CardManager signer = new CardManager();
                signer.readCardData(cardPin);
                if (reallySign) {
                    signer.getKeyStore(cardPin);
                    DataSource signed = signer.sign(signingBean, addArchiveInfo, signingBean.getWalker());
                    util.writeToFile(signed, signingBean);
                }
            } else if (!cardSigning.isSelected() && !signLoacal.isSelected()) {
                GSON.Params params = new GSON.Params();
                GSON.Signing signing = new GSON.Signing();
                params.signing = signing;
                params.parmType = "docSign";
                params.signing.signatureType = signingBean.getSignatureType().name();
                params.signing.mode = signingBean.getSigningMode().getMode();
                if (signingBean.getSignatureAlgorithm() != null) {
                    params.signing.signatureAlgorithm = signingBean.getSignatureAlgorithm().getName();
                }
                if (signingBean.getDigestAlgorithm() != null) {
                    params.signing.digestAlgorithm = signingBean.getDigestAlgorithm().getName();
                    if (attributeCertificate != null) {
                        params.signing.attributeCert = Util.toBase64String(attributeCertificate.getEncoded());
                    }
                }
                if (signingBean.getSignatureType().equals(SigningBean.SigningType.CAdES)) {
                    GSON.SigningCAdES cades = new GSON.SigningCAdES();
                    params.signing.cadesParams = cades;
                    params.signing.cadesParams.TSAURL = signingBean.getTspURL();
                    params.signing.cadesParams.addArchiveinfo = addArchiveInfo;
                }
                HttpClientConnection
                        .sendDocSigningRequest(signingBean.getDataIN(),
                                params, new File(signingBean.getOutputPath()));

            } else if (!cardSigning.isSelected() && signLoacal.isSelected()) {
                if (signingBean.getSignatureType().equals(SigningBean.SigningType.CAdES)) {
                    DataSource ds = util.signCAdES(signingBean, archiveInfo.isSelected());
                    util.writeToFile(ds, signingBean);

                }
                else if (signingBean.getSignatureType().equals(SigningBean.SigningType.CMS)) {
                    DataSource ds = util.signCMS(signingBean);
                    util.writeToFile(ds, signingBean);

                }
                else if (signingBean.getSignatureType().equals(SigningBean.SigningType.PAdES)) {
                    CertWriterReader.KeyStoreBean bean = signingBean.getKeyStoreBean();
                    SignPDFUtil pdfUtil = new SignPDFUtil(bean.getSelectedKey(), bean.getChain());
                    PadesBESParameters params = pdfUtil.createParameters(signingBean);
                    DataSource ds = pdfUtil.signPDF(signingBean, params, "IAIK");
                    util.writeToFile(ds, signingBean);
                }
            } else if (signingBean.getAction().equals(CMSSigner.Commands.ENCRYPT_SIGN)) {
                Tuple<DataSource, DataSource> outCome = util.encryptAndSign(signingBean);
                util.writeToFile(outCome.getSecond(), signingBean);
            }
        }

    }

    @FXML
    public void selectIN(ActionEvent event) throws Exception {
        File inFile = showOpenDialog(event, "dataIN");
        signingBean.setDataINFile(inFile).setDataIN(new FileInputStream(inFile));
    }

    @FXML
    public void selectOut(ActionEvent event) throws Exception {
        File outFile = showSaveDialog(event, "signatureOut");
        signingBean.setOutputPath(outFile.getAbsolutePath());
    }

    @FXML
    public void selectStore(ActionEvent event) throws Exception {
        keystoreFile = showOpenDialog(event, "keyStoreLoc");
    }

    @FXML
    public void loadStore(ActionEvent event) throws Exception {
        store = KeyStoreTool
                .loadStore(new FileInputStream(keystoreFile),
                        pin.getText().toCharArray(),
                        "PKCS12");
        Enumeration<String> aliases = store.aliases();
        while(aliases.hasMoreElements()) {
            aliasBox.getItems().add(aliases.nextElement());
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
