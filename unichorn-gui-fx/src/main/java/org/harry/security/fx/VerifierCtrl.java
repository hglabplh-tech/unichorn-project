package org.harry.security.fx;

import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.*;
import org.etsi.uri._02231.v2_.TrustStatusListType;
import org.harry.security.util.ConfigReader;
import org.harry.security.util.Tuple;
import org.harry.security.util.VerifyUtil;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.trustlist.TrustListWalkerAndGetter;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.harry.security.fx.util.Miscellaneous.*;
import static org.harry.security.util.ConfigReader.downloadTrusts;

public class VerifierCtrl implements ControllerInit {

    @FXML private TableView<ResultEntry> verifyResults;
    private SigningBean bean;

    private File signatureInput = null;

    File inputPath = null;

    @Override
    public Scene init() {
        bean = SecHarry.contexts.get();
        TextField dataPathField = getTextFieldByFXID("nonEditDataPath");
        inputPath = bean.getDataINPath();
        ComboBox sigType = getComboBoxByFXID("sigType");
        sigType.getItems().addAll(SigningBean.SigningType.values());

        if (inputPath != null) {
            dataPathField.setText(inputPath.getAbsolutePath());
        }

        return dataPathField.getScene();
    }

    @FXML
    public void goBack(ActionEvent event) throws IOException {
        SecHarry.setRoot("main");
    }

    @FXML
    public void verify(ActionEvent event) throws IOException {
        verifyResults.getSelectionModel().setCellSelectionEnabled(true);
        verifyResults.setEditable(false);
        verifyResults.getSelectionModel().getSelectedItem();
        SigningBean bean = SecHarry.contexts.get();
        CheckBox check = getCheckBoxByFXID("ocspPathCheck");
        ProgressBar progress = getProgessBarByFXID("progress");
        progress.setProgress(25.0d);
        ComboBox sigType = getComboBoxByFXID("sigType");
        SigningBean.SigningType type = (SigningBean.SigningType) sigType.getSelectionModel().getSelectedItem();
        boolean ocspPathCheck = check.isSelected();
        bean.setCheckPathOcsp(ocspPathCheck);
        VerifyUtil util = new VerifyUtil(bean.getWalker(), bean);
        InputStream dataIN = null;
        InputStream signatureIN = null;
        if (inputPath != null && signatureInput != null) {
            signatureIN = new FileInputStream(signatureInput);
            dataIN = new FileInputStream(inputPath);
            if(type.equals(SigningBean.SigningType.CMS)) {
                progress.setProgress(50.0d);
                VerifyUtil.VerifierResult result = util.verifyCMSSignature(signatureIN, dataIN);
                List<VerifyUtil.SignerInfoCheckResults> set = result.getSignersCheck();
                List<ResultEntry> entryList = new ArrayList<>();
                for (VerifyUtil.SignerInfoCheckResults entry : set) {
                    Map<String, Tuple<String, VerifyUtil.Outcome>> sigResult = entry.getSignatureResult();
                    Map<String, Tuple<String, VerifyUtil.Outcome>> ocspResult = entry.getOcspResult();
                    for (Map.Entry<String, Tuple<String, VerifyUtil.Outcome>> sigEntry : sigResult.entrySet()) {
                        ResultEntry propEntry = new ResultEntry(sigEntry.getKey(), sigEntry.getValue().getFirst(),
                                sigEntry.getValue().getSecond().name());
                        entryList.add(propEntry);
                    }

                    for (Map.Entry<String, Tuple<String, VerifyUtil.Outcome>> ocspEntry : ocspResult.entrySet()) {
                        ResultEntry propEntry = new ResultEntry(ocspEntry.getKey(), ocspEntry.getValue().getFirst(),
                                ocspEntry.getValue().getSecond().name());
                        entryList.add(propEntry);
                    }
                    ObservableList<ResultEntry> data = verifyResults.getItems();
                    entry.getSignersChain();
                    data.clear();
                    verifyResults.setVisible(false);
                    data.addAll(entryList);
                }
            } else {
                progress.setProgress(50.0d);
                VerifyUtil.VerifierResult result  = util.verifyCadesSignature(signatureIN, dataIN);
                List<VerifyUtil.SignerInfoCheckResults> set = result.getSignersCheck();
                List<ResultEntry> entryList = new ArrayList<>();
                for (VerifyUtil.SignerInfoCheckResults entry : set) {
                    Map<String, Tuple<String, VerifyUtil.Outcome>> sigResult = entry.getSignatureResult();
                    Map<String, Tuple<String, VerifyUtil.Outcome>> ocspResult = entry.getOcspResult();
                    for (Map.Entry<String, Tuple<String, VerifyUtil.Outcome>> sigEntry : sigResult.entrySet()) {
                        ResultEntry propEntry = new ResultEntry(sigEntry.getKey(), sigEntry.getValue().getFirst(),
                                sigEntry.getValue().getSecond().name());
                        entryList.add(propEntry);
                    }

                    for (Map.Entry<String, Tuple<String, VerifyUtil.Outcome>> ocspEntry : ocspResult.entrySet()) {
                        ResultEntry propEntry = new ResultEntry(ocspEntry.getKey(), ocspEntry.getValue().getFirst(),
                                ocspEntry.getValue().getSecond().name());
                        entryList.add(propEntry);
                    }
                    ObservableList<ResultEntry> data = verifyResults.getItems();
                    entry.getSignersChain();
                    data.clear();
                    verifyResults.setVisible(false);
                    data.addAll(entryList);
                }
            }

            verifyResults.refresh();
            verifyResults.setVisible(true);
        }
    }

    @FXML
    public void signatureSelect(ActionEvent event) {
        String fxId = "signatureIN";
        signatureInput = showOpenDialog(event, fxId);
    }

    @FXML
    public void downloadTrust(ActionEvent event) {
        SigningBean bean = SecHarry.contexts.get();
        ConfigReader.MainProperties params = ConfigReader.loadStore();
        downloadTrusts(params.getTrustLists());
        TrustStatusListType loaded = ConfigReader.loadSpecificTrust("TL-DE");
        List<TrustListWalkerAndGetter> walkers = ConfigReader.loadAllTrusts();
        bean.setWalker(walkers);
        SecHarry.contexts.set(bean);
    }
}
