package org.harald.security.fx;

import iaik.x509.X509Certificate;
import iaik.x509.attr.AttributeCertificate;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.TextField;
import org.harry.security.util.CertificateWizzard;
import org.harry.security.util.Tuple;
import org.harry.security.util.bean.AttrCertBean;
import org.harry.security.util.certandkey.KeyStoreTool;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;

import static org.harald.security.fx.util.Miscellaneous.getTextFieldByFXID;
import static org.harald.security.fx.util.Miscellaneous.showSaveDialog;

public class AttribueCertCtrl implements ControllerInit {

    File attrCertFile;

    @Override
    public Scene init() {
        return null;
    }

    @FXML
    public void save(ActionEvent event) throws IOException {
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        AttrCertBean bean = fillAttrCertBean();
        AttributeCertificate attrCert = CertificateWizzard.createAttributeCertificate(keys.getSecond()[0],
                keys.getSecond()[1],
                keys.getFirst(),
                bean);
        OutputStream out = new FileOutputStream(attrCertFile);
        attrCert.writeTo(out);
        out.flush();
        out.close();
    }

    @FXML
    public void goBack(ActionEvent event) throws Exception {
        SecHarry.setRoot("main", SecHarry.CSS.UNICHORN);
    }

    @FXML
    public void selectOut(ActionEvent event) {
        attrCertFile = showSaveDialog(event, "outputFile");
    }

    private AttrCertBean fillAttrCertBean() {
        TextField roleName = getTextFieldByFXID("roleName");
        TextField commonName = getTextFieldByFXID("commonName");
        TextField targetGroup = getTextFieldByFXID("targetGroup");
        TextField authCountry = getTextFieldByFXID("authCountry");
        TextField targetName = getTextFieldByFXID("targetName");
        TextField authOrg = getTextFieldByFXID("authOrg");
        TextField authOrgUnit = getTextFieldByFXID("authOrgUnit");
        TextField authCommon = getTextFieldByFXID("authCommon");
        TextField accessID = getTextFieldByFXID("accessID");
        TextField accessIDService = getTextFieldByFXID("accessIDService");
        TextField groupValue1 = getTextFieldByFXID("groupValue1");
        TextField groupValue2 = getTextFieldByFXID("groupValue2");
        TextField category = getTextFieldByFXID("category");
        String[] targetNames = new String[]{targetName.getText(), targetName.getText(), targetName.getText(), targetName.getText()};

        AttrCertBean attrBean = new AttrCertBean()
                .setRoleName(roleName.getText())
                .setCommonName(commonName.getText())
                .setTargetName(targetName.getText())
                .setTargetNames(targetNames)
                .setTargetGroup(targetGroup.getText())
                .setAuthCountry(authCountry.getText())
                .setAuthOrganization(authOrg.getText())
                .setAuthOrganizationalUnit(authOrgUnit.getText())
                .setAuthCommonName(authCommon.getText())
                .setCategory(category.getText())
                .setAccessIdentityService(accessIDService.getText())
                .setAccessIdentityIdent(accessID.getText())
                .setGroupValue1(groupValue1.getText())
                .setGroupValue2(groupValue2.getText());
        return attrBean;
    }
}
