package org.harald.security.fx;

import iaik.utils.Util;
import iaik.x509.X509Certificate;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.ListChangeListener;
import javafx.concurrent.Worker;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.web.*;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.util.Callback;
import org.harry.security.util.HttpsChecker;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.pwdmanager.PasswordManager;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Properties;

import static org.harald.security.fx.util.Miscellaneous.*;
import static org.harry.security.CommonConst.APP_DIR;
import static org.harry.security.util.certandkey.KeyStoreTool.KEYSTORE_FNAME;

public class BrowserCtrl implements ControllerInit {

    @FXML private ProgressBar progress;
    private WebEngine engine = null;
    private String nextUrlString = "https://www.google.de";
    private URL nextUrl = null;
    private int webIndex = 0;
    private Properties bookmarkList = new Properties();
    @Override
    public Scene init() {
        return null;
    }

    public void setTabContent(Tab tab) throws IOException {
        Parent parent = SecHarry.loadFXML("browserTab", SecHarry.CSS.UNICHORN);
        tab.setContent(parent);
    }

}
