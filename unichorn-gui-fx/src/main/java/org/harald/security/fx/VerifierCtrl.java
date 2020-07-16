package org.harald.security.fx;

import iaik.x509.X509Certificate;
import iaik.x509.ocsp.OCSPResponse;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.*;
import org.etsi.uri._02231.v2_.TrustStatusListType;
import org.harry.security.util.*;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.ocsp.OCSPCRLClient;
import org.harry.security.util.trustlist.TrustListManager;

import java.io.*;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.harald.security.fx.util.Miscellaneous.*;
import static org.harry.security.util.ConfigReader.downloadTrusts;

public class VerifierCtrl implements ControllerInit {

    @FXML private TableView<ResultEntry> verifyResults;
    private SigningBean signingBean;

    private File signatureInput = null;

    File inputPath = null;

    @Override
    public Scene init() {
        signingBean = contexts.get().getBean();
        TextField dataPathField = getTextFieldByFXID("dataPath");
        inputPath = signingBean.getDataINPath();
        ComboBox sigType = getComboBoxByFXID("sigType");
        sigType.getItems().addAll(SigningBean.SigningType.values());

        if (inputPath != null) {
            dataPathField.setText(inputPath.getAbsolutePath());
        }

        return dataPathField.getScene();
    }

    @FXML
    public void goBack(ActionEvent event) throws IOException {
        SecHarry.setRoot("main", SecHarry.CSS.UNICHORN);
    }

    @FXML
    public void verify(ActionEvent event) throws Exception {
        verifyResults.getSelectionModel().setCellSelectionEnabled(true);
        verifyResults.setEditable(false);
        verifyResults.getSelectionModel().getSelectedItem();
        signingBean = contexts.get().getBean();
        CheckBox check = getCheckBoxByFXID("ocspPathCheck");
        CheckBox altResponder = getCheckBoxByFXID("altResponder");
        Label status = getLabelByFXID("status");

        ComboBox sigType = getComboBoxByFXID("sigType");
        SigningBean.SigningType type = (SigningBean.SigningType) sigType.getSelectionModel().getSelectedItem();
        boolean ocspPathCheck = check.isSelected();
        boolean altResp = altResponder.isSelected();
        signingBean = signingBean.setCheckOcspUseAltResponder(altResp);
        signingBean.setCheckPathOcsp(ocspPathCheck);
        VerifyUtil util = new VerifyUtil(signingBean.getWalker(), signingBean);
        InputStream dataIN = null;
        InputStream signatureIN = null;
        if (inputPath != null && signatureInput != null) {
            signatureIN = new FileInputStream(signatureInput);
            dataIN = new FileInputStream(inputPath);
            if (type.equals(SigningBean.SigningType.CMS)) {

                VerificationResults.VerifierResult result = util.verifyCMSSignature(signatureIN, dataIN);
                List<VerificationResults.SignerInfoCheckResults> set = result.getSignersCheck();
                List<ResultEntry> entryList = new ArrayList<>();
                for (VerificationResults.SignerInfoCheckResults entry : set) {
                    X509Certificate[] signerChain = entry.getSignerChain();
                    Map<String, Tuple<String, VerificationResults.Outcome>> sigResult = entry.getSignatureResult();
                    Map<String, Tuple<OCSPResponse, VerificationResults.Outcome>> ocspResult = entry.getOcspResult();
                    for (Map.Entry<String, Tuple<String, VerificationResults.Outcome>> sigEntry : sigResult.entrySet()) {
                        ResultEntry propEntry = new ResultEntry(sigEntry.getKey(), sigEntry.getValue().getFirst(),
                                sigEntry.getValue().getSecond().name());
                        entryList.add(propEntry);
                    }

                    for (Map.Entry<String, Tuple<OCSPResponse, VerificationResults.Outcome>> ocspEntry : ocspResult.entrySet()) {
                        ResultEntry propEntry = new ResultEntry(ocspEntry.getKey(),
                                OCSPCRLClient.extractResponseStatusName(ocspEntry.getValue().getFirst()),
                                ocspEntry.getValue().getSecond().name());
                        entryList.add(propEntry);
                    }
                    ObservableList<ResultEntry> data = verifyResults.getItems();
                    entry.getSignersChain();
                    data.clear();
                    verifyResults.setVisible(false);
                    data.addAll(entryList);
                    if (signerChain != null) {
                        KeyStore store = KeyStoreTool.initStore("UnicP12", "geheim");
                        KeyStoreTool.addCertificateChain(store, signerChain);
                        ConfigReader.MainProperties props = ConfigReader.loadStore();
                        KeyStoreTool.storeKeyStore(store, new FileOutputStream(props.getKeystorePath()), "geheim".toCharArray());
                    }
                }
            } else if (type.equals(SigningBean.SigningType.CAdES)) {
                VerificationResults.VerifierResult result = util.verifyCadesSignature(signatureIN, dataIN);
                List<VerificationResults.SignerInfoCheckResults> set = result.getSignersCheck();
                List<ResultEntry> entryList = new ArrayList<>();
                for (VerificationResults.SignerInfoCheckResults entry : set) {
                    X509Certificate[] signerChain = entry.getSignerChain();
                    Map<String, Tuple<String, VerificationResults.Outcome>> sigResult = entry.getSignatureResult();
                    Map<String, Tuple<OCSPResponse, VerificationResults.Outcome>> ocspResult = entry.getOcspResult();
                    for (Map.Entry<String, Tuple<String, VerificationResults.Outcome>> sigEntry : sigResult.entrySet()) {
                        ResultEntry propEntry = new ResultEntry(sigEntry.getKey(), sigEntry.getValue().getFirst(),
                                sigEntry.getValue().getSecond().name());
                        entryList.add(propEntry);
                    }

                    for (Map.Entry<String, Tuple<OCSPResponse, VerificationResults.Outcome>> ocspEntry : ocspResult.entrySet()) {
                        ResultEntry propEntry = new ResultEntry(ocspEntry.getKey(),
                                OCSPCRLClient.extractResponseStatusName(ocspEntry.getValue().getFirst()),
                                ocspEntry.getValue().getSecond().name());
                        entryList.add(propEntry);
                    }
                    ObservableList<ResultEntry> data = verifyResults.getItems();
                    entry.getSignersChain();
                    data.clear();
                    data.addAll(entryList);
                    if (signerChain != null && signerChain.length == 3) {
                        KeyStore store = KeyStoreTool.initStore("UnicP12", "geheim");
                        KeyStoreTool.addCertificateChain(store, signerChain);
                        ConfigReader.MainProperties props = ConfigReader.loadStore();
                        KeyStoreTool.storeKeyStore(store, new FileOutputStream(props.getKeystorePath()), "geheim".toCharArray());
                    }
                }
            }
        } else if (signatureInput != null) {
            signatureIN = new FileInputStream(signatureInput);
            if (type.equals(SigningBean.SigningType.PAdES)) {
                VerifyPDFUtil pdfUtil = new VerifyPDFUtil(signingBean.getWalker(), signingBean);
                VerificationResults.VerifierResult result = pdfUtil.verifySignedPdf(signatureIN);
                List<VerificationResults.SignerInfoCheckResults> set = result.getSignersCheck();
                List<ResultEntry> entryList = new ArrayList<>();
                for (VerificationResults.SignerInfoCheckResults entry : set) {
                    X509Certificate[] signerChain = entry.getSignerChain();
                    Map<String, Tuple<String, VerificationResults.Outcome>> sigResult = entry.getSignatureResult();
                    Map<String, Tuple<OCSPResponse, VerificationResults.Outcome>> ocspResult = entry.getOcspResult();
                    for (Map.Entry<String, Tuple<String, VerificationResults.Outcome>> sigEntry : sigResult.entrySet()) {
                        ResultEntry propEntry = new ResultEntry(sigEntry.getKey(), sigEntry.getValue().getFirst(),
                                sigEntry.getValue().getSecond().name());
                        entryList.add(propEntry);
                    }

                    for (Map.Entry<String, Tuple<OCSPResponse, VerificationResults.Outcome>> ocspEntry : ocspResult.entrySet()) {
                        ResultEntry propEntry = new ResultEntry(ocspEntry.getKey(),
                                OCSPCRLClient.extractResponseStatusName(ocspEntry.getValue().getFirst()),
                                ocspEntry.getValue().getSecond().name());
                        entryList.add(propEntry);
                    }
                    ObservableList<ResultEntry> data = verifyResults.getItems();
                    entry.getSignersChain();
                    data.clear();
                    data.addAll(entryList);
                    if (signerChain != null && signerChain.length == 3) {
                        KeyStore store = KeyStoreTool.initStore("UnicP12", "geheim");
                        KeyStoreTool.addCertificateChain(store, signerChain);
                        ConfigReader.MainProperties props = ConfigReader.loadStore();
                        KeyStoreTool.storeKeyStore(store, new FileOutputStream(props.getKeystorePath()), "geheim".toCharArray());
                    }
                }
            }
            status.setText("File checked with: " + type.name());
            verifyResults.refresh();
            verifyResults.setVisible(true);

        }

    }

    @FXML
    public void selectData(ActionEvent event) throws IOException {
        String fxId = "dataPath";
        inputPath = showOpenDialog(event, fxId);
        signingBean.setDataINPath(inputPath).setDataIN(new FileInputStream(inputPath)).setDataINFile(inputPath);

    }
    @FXML
    public void signatureSelect(ActionEvent event)  {
        String fxId = "signatureIN";
        signatureInput = showOpenDialog(event, fxId);
    }

    @FXML
    public void downloadTrust(ActionEvent event) {
        SigningBean bean = contexts.get().getBean();
        ConfigReader.MainProperties params = ConfigReader.loadStore();
        downloadTrusts(params.getTrustLists());
        TrustStatusListType loaded = ConfigReader.loadSpecificTrust("TL-DE");
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        bean.setWalker(walkers);
        contexts.get().setBean(bean);
    }
}
