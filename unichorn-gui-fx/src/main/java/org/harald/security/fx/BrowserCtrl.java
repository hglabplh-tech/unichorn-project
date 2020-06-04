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
        loadBookmarks();
        File keyFile = new File(APP_DIR, KEYSTORE_FNAME);
        System.setProperty("javax.net.ssl.keyStore", keyFile.getAbsolutePath());
        System.setProperty("javax.net.ssl.keyStorePassword","geheim");
        WebView webViewer = getWebViewByFXID("browser");
        engine = webViewer.getEngine();
        progress = getProgessBarByFXID("progress");

        WebView wv = new WebView();
        engine.setCreatePopupHandler(new Callback<PopupFeatures, WebEngine>() {

            @Override
            public WebEngine call(PopupFeatures p) {
                Stage stage = new Stage(StageStyle.UTILITY);
                WebView webViewSecond = new WebView();
                stage.setScene(new Scene(webViewSecond));
                stage.show();
                return webViewSecond.getEngine();
            }
        });

        engine.setOnAlert(new EventHandler<WebEvent<String>>() {
            @Override
            public void handle(WebEvent<String> arg0) {
                System.out.println("alert: " + arg0);
            }
        });
        Worker<Void> worker = engine.getLoadWorker();
        engine.getLoadWorker().progressProperty().addListener(new ChangeListener<Number>() {
            @Override
            public void changed(ObservableValue<? extends Number> arg0, Number arg1, Number arg2) {
                System.out.println("Process changed: " + arg0 + ", arg1: " + arg1 + ", arg2: " + arg2);
            }
        });

        final WebHistory history = engine.getHistory();
        history.getEntries().addListener(new     ListChangeListener<WebHistory.Entry>() {
                                                     @Override
                                                     public void onChanged(Change<? extends WebHistory.Entry> c) {
                                                         ComboBox comboBox = getComboBoxByFXID("history");
                                                         c.next();
                                                         for (WebHistory.Entry e : c.getRemoved()) {
                                                             comboBox.getItems().remove(e.getUrl());
                                                         }
                                                         for (WebHistory.Entry e : c.getAddedSubList()) {
                                                             comboBox.getItems().add(e.getUrl());
                                                         }
                                                     }
                                                 }
        );




        engine.getLoadWorker().exceptionProperty().addListener(new ChangeListener<Throwable>() {
            @Override
            public void changed(ObservableValue<? extends Throwable> arg0, Throwable arg1, Throwable arg2) {
                System.out.println(arg0);
                if (arg1 != null) {
                    System.out.println(arg1);
                    arg1.printStackTrace();
                }
                if (arg2 != null) {
                    System.out.println(arg2);
                    arg2.printStackTrace();
                }
            }
        });
        worker.stateProperty().addListener(new ChangeListener<Worker.State>() {
            @Override
            public void changed(ObservableValue<? extends Worker.State> observable, Worker.State oldValue, Worker.State newValue) {
                TextField address = getTextFieldByFXID("address");
                CheckBox ocspCheck = getCheckBoxByFXID("ocspCheck");
                Label label = getLabelByFXID("status");
                nextUrlString = engine.getLocation();
                address.setText(nextUrlString);

                if (newValue == Worker.State.SUCCEEDED) {
                    try {
                        if (nextUrl.getProtocol().startsWith("https") && !isHostLocal(nextUrl.getHost())) {
                            Tuple<Integer, List<X509Certificate>> tuple =
                                    HttpsChecker.checkHttpsCertValidity(nextUrlString, ocspCheck.isSelected(), false);
                            if (tuple.getFirst() == 0) {
                                if (ocspCheck.isSelected()) {
                                    label.setText("web-site is secure");
                                } else {
                                    label.setText("identity checked ok");
                                }
                            } else {
                                label.setText("no security info available");
                            }
                        }
                    } catch (Exception ex) {
                        throw new IllegalStateException("load failed", ex);
                    }
                    // hide progress bar then page is ready

                    progress.setVisible(false);
                } else if (newValue == Worker.State.RUNNING) {
                    String base64 = getBasicAuth(nextUrlString);
                    engine.setUserAgent("foo\nAuthorization: Basic " + base64);
                    progress.progressProperty().bind(engine.getLoadWorker().progressProperty());
                    TrustManager trm = new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(java.security.cert.X509Certificate[] x509Certificates, String s) throws CertificateException {

                        }

                        @Override
                        public void checkServerTrusted(java.security.cert.X509Certificate[] x509Certificates, String s) throws CertificateException {

                        }

                        @Override
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return new java.security.cert.X509Certificate[0];
                        }
                    };

                    SSLContext sc = null;
                    try {

                        try {
                            nextUrl = new URL(nextUrlString);
                        } catch (MalformedURLException e) {
                            e.printStackTrace();
                        }
                        sc = SSLContext.getInstance("SSL");
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    }
                    try {
                        sc.init(null, new TrustManager[] { trm }, null);
                    } catch (KeyManagementException e) {
                        e.printStackTrace();
                    }

                    if (isHostLocal(nextUrl.getHost()))
                    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
                    HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                        @Override
                        public boolean verify(String s, SSLSession sslSession) {
                            return true;
                        }
                    });
                    progress.setVisible(true);

                    try {

                    } catch (Exception e) {

                    }
                }
            }
        });
        engine.load(nextUrlString);
        return webViewer.getScene();
    }

    @FXML
    public void load(ActionEvent event) throws IOException {
        Object source = event.getSource();
        if (source instanceof TextField) {
            TextField address = getTextFieldByFXID("address");
            nextUrlString = address.getText();
        } else if (source instanceof ComboBox) {
            ComboBox bookmark = getComboBoxByFXID("bookmarks");
            String title = (String)bookmark.getSelectionModel().getSelectedItem();
            nextUrlString = bookmarkList.getProperty(title);
            File bookmarkFile = new File(KeyStoreTool.APP_DIR, "bookmarks.properties");
            bookmarkList.storeToXML(new FileOutputStream(bookmarkFile), "bookmarks");
        }
        engine.load(nextUrlString);
    }

    @FXML
    public void back(ActionEvent event) throws IOException {
        SecHarry.setRoot("main", SecHarry.CSS.UNICHORN);
    }

    @FXML
    public void history(ActionEvent event) throws IOException {
        WebHistory history = engine.getHistory();
        ComboBox comboBox = getComboBoxByFXID("history");
        int offset =
                comboBox.getSelectionModel().getSelectedIndex()
                        - history.getCurrentIndex();
        history.go(offset);
        progress.progressProperty().bind(engine.getLoadWorker().progressProperty());
        progress.setVisible(true);
    }

    @FXML
    public void backward(ActionEvent event) throws IOException {
        WebHistory history = engine.getHistory();
        if (webIndex < 0) {
            String url = history.getEntries().get(0).getUrl();
            nextUrlString = url;
            engine.load(nextUrlString);
            progress.progressProperty().bind(engine.getLoadWorker().progressProperty());
            progress.setVisible(true);
        } else if (webIndex == history.getEntries().size()) {
            String url = history.getEntries().get(webIndex -1).getUrl();
            nextUrlString = url;
            engine.load(nextUrlString);
            progress.progressProperty().bind(engine.getLoadWorker().progressProperty());
            progress.setVisible(true);
            webIndex--;
        } else {
            String url = history.getEntries().get(webIndex).getUrl();
            nextUrlString = url;
            engine.load(nextUrlString);
            progress.progressProperty().bind(engine.getLoadWorker().progressProperty());
            progress.setVisible(true);
            webIndex--;
        }
    }

    @FXML
    public void createPasswd(ActionEvent event) throws IOException {
        TextField masterPass = getTextFieldByFXID("masterPass");
        String masterPW = masterPass.getText();
        if (masterPW != null && !masterPW.isEmpty()) {
            StorePasswdDialog.passwordStoreDialog(masterPW, false);
        }
    }

    @FXML
    public void bookmarkit(ActionEvent event) {
        ComboBox bookmark = getComboBoxByFXID("bookmarks");
        WebHistory history = engine.getHistory();
        WebHistory.Entry entry = history.getEntries().get(history.getCurrentIndex());
        String key;
        if (entry.getTitle() != null && !entry.getTitle().isEmpty()) {
            key = entry.getTitle();
        } else {
            key = entry.getUrl();
        }
        bookmarkList.setProperty(key, entry.getUrl());
        bookmark.getItems().add(key);
    }

    private boolean isHostLocal(String host) {
        return (("localhost".equals(host)) || ("127.0.0.1".equals(host)));
    }

    private String getBasicAuth(String url) {
        TextField masterPass = getTextFieldByFXID("masterPass");
        String masterPW = masterPass.getText();
        PasswordManager manager = new PasswordManager(masterPW);
        Tuple<String, String> result = manager.readPassword(url);
        String authString = "dummy";
        if (result != null) {
            authString = String.format("%s:%s", result.getFirst(), result.getSecond());
        }
        return Util.toBase64String(authString.getBytes());
    }

    private void loadBookmarks() {
        try {
            File bookmarkFile = new File(KeyStoreTool.APP_DIR, "bookmarks.properties");
            if (bookmarkFile.exists()) {
                bookmarkList.loadFromXML(new FileInputStream(bookmarkFile));
                ComboBox bookmarkCombo = getComboBoxByFXID("bookmarks");
                bookmarkCombo.getItems().addAll(bookmarkList.keySet());
            }
        } catch (Exception ex) {
            throw new IllegalStateException("loading bookmarks failed....", ex);
        }
    }

}
