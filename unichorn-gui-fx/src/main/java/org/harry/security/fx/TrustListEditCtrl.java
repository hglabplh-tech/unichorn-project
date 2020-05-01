package org.harry.security.fx;

import com.sun.tools.rngom.ast.builder.GrammarSection;
import iaik.x509.X509Certificate;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TextField;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.httpclient.HttpClientConnection;
import org.harry.security.util.trustlist.TrustListLoader;
import org.harry.security.util.trustlist.TrustListManager;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Enumeration;
import java.util.List;
import java.util.Vector;

import static org.harry.security.fx.util.Miscellaneous.*;

public class TrustListEditCtrl implements ControllerInit {

    private File keyStoreFile;

    private File trustListFile;

    private File trustListFileOut;

    private TrustListManager manager;

    private TrustListLoader loader;

    @Override
    public Scene init() {
        return null;
    }

    @FXML
    public void selectStore(ActionEvent event) {
        keyStoreFile = showOpenDialog(event, "keyStoreLoc");
    }
    @FXML
    public void selectFile(ActionEvent event) throws IOException  {
        trustListFile = showOpenDialog(event, "trustFile");
        loader = new TrustListLoader();
        manager = loader.getManager(trustListFile);
        List<Vector<String>> paths = manager.collectPaths();
        ComboBox pathBox = getComboBoxByFXID("paths");
        for(Vector<String> path: paths) {
            String pathString = path.get(0) + "/" + path.get(1);
            pathBox.getItems().add(pathString);
        }
    }

    @FXML
    public void selectOut(ActionEvent event) throws IOException  {
        trustListFileOut = showSaveDialog(event, "trustOut");
    }

    @FXML
    public void save(ActionEvent event)  {
        ComboBox pathBox = getComboBoxByFXID("paths");
        TextField passwd = getTextFieldByFXID("passwd");
        String pathString = (String)pathBox.getSelectionModel().getSelectedItem();
        try {
            String[] list = pathString.split("/");
            Vector<String> path = new Vector<>();
            path.addElement(list[0]);
            path.addElement(list[1]);
            KeyStore store = KeyStoreTool.loadStore(new FileInputStream(keyStoreFile),
                    passwd.getText().toCharArray(),
                    "JKS");
            Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool
                        .getKeyEntry(store, alias, passwd.getText().toCharArray());
                for (X509Certificate cert : keys.getSecond()) {
                    manager.addX509Cert(path, cert);
                }

            }
            FileOutputStream out = new FileOutputStream(trustListFileOut);
            loader.storeTrust(out);
            FileInputStream input = new FileInputStream(trustListFileOut);
            HttpClientConnection.sendPutData(input, "trust");
            SecHarry.setRoot("main", SecHarry.CSS.ABBY);
        } catch(Exception ex) {
            throw new IllegalStateException("save trust failed", ex);
        }
    }
    @FXML
    public void back(ActionEvent event) throws IOException {
        SecHarry.setRoot("main", SecHarry.CSS.UNICHORN);
    }
}
