package org.harald.security.fx;


import iaik.security.provider.IAIKMD;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import javafx.application.Platform;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.ListChangeListener;
import javafx.concurrent.Task;
import javafx.concurrent.Worker;
import javafx.event.ActionEvent;
import javafx.event.Event;
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
import org.harry.security.util.httpclient.ClientFactory;
import org.harry.security.util.httpclient.SSLUtils;
import org.harry.security.util.pwdmanager.PasswordManager;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.*;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

import static org.harald.security.fx.SecHarry.bookmarkLocal;
import static org.harald.security.fx.util.Miscellaneous.getTabByFXID;
import static org.harald.security.fx.util.Miscellaneous.getTabPaneByFXID;
import static org.harry.security.CommonConst.APP_DIR;
import static org.harry.security.util.certandkey.KeyStoreTool.KEYSTORE_FNAME;

public class BrowserTabCtrl  implements ControllerInit {

    @FXML private ProgressBar progress;
    @FXML private ComboBox bookmarks;
    @FXML private WebView browser;
    @FXML private TextField address;
    @FXML public  Label status;
    @FXML private CheckBox ocspCheck;
    @FXML private ComboBox history;
    @FXML private TextField masterPass;

    HttpsCheckerTask task;


    private WebEngine engine = null;
    private String nextUrlString = "https://www.google.de";
    private URL nextUrl = null;
    private int webIndex = 0;




    @FXML
    protected void initialize() {

        IAIKMD.addAsProvider();

        loadBookmarks();
        File keyFile = new File(APP_DIR, KEYSTORE_FNAME);
        System.setProperty("javax.net.ssl.keyStore", keyFile.getAbsolutePath());
        System.setProperty("javax.net.ssl.keyStorePassword","geheim");
        WebView webViewer = browser;
        engine = webViewer.getEngine();


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


        final WebHistory webHistory = engine.getHistory();
        webHistory.getEntries().addListener(new     ListChangeListener<WebHistory.Entry>() {
                                                     @Override
                                                     public void onChanged(Change<? extends WebHistory.Entry> c) {
                                                         ComboBox comboBox = history;
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





        engine.getLoadWorker().stateProperty().addListener(new ChangeListener<Worker.State>() {
            @Override
            public void changed(ObservableValue<? extends Worker.State> observable, Worker.State oldValue, Worker.State newValue) {
                Label label = status;
                nextUrlString = engine.getLocation();
                Worker.State p = observable.getValue();
                address.setText(nextUrlString);

                if (newValue == Worker.State.SUCCEEDED) {
                    try {
                        startChecker();
                    } catch (Exception ex) {
                        throw new IllegalStateException("load failed", ex);
                    }
                    // hide progress bar then page is ready

                    progress.setVisible(false);
                } else if (newValue == Worker.State.FAILED || newValue == Worker.State.CANCELLED) {
                    progress.setVisible(false);
                } else if (newValue == Worker.State.RUNNING) {
                    try {
                        nextUrl = new URL(nextUrlString);
                    } catch (MalformedURLException e) {
                        e.printStackTrace();
                    }
                    if (SSLUtils.isHostLocal(nextUrl.getHost())) {
                        String base64 = getBasicAuth(nextUrlString);
                        if (base64 != null) { // means that we have a login for this page
                            engine.setUserAgent("foo\nAuthorization: Basic " + base64);
                        }
                    }
                    try {
                    SSLContext sslContext = null;
                    if (SSLUtils.isHostLocal(nextUrl.getHost())) {
                        sslContext = SSLUtils.trustReallyAllShit();
                    } else {
                        sslContext = SSLUtils.createStandardContext("TLS");
                    }
                    if (SSLUtils.isHostLocal(nextUrl.getHost())) {
                        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
                        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
                        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                            @Override
                            public boolean verify(String s, SSLSession sslSession) {
                                return true;
                            }
                        });
                        SSLContext.setDefault(sslContext);
                    } else {
                        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "false");
                        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
                        SSLContext.setDefault(sslContext);
                    }
                } catch(Exception ex) {
                    throw new IllegalStateException(ex.getMessage());
                }
                    progress.progressProperty().bind(engine.getLoadWorker().progressProperty());
                    progress.setVisible(true);
                }
            }

        });
        engine.getLoadWorker().exceptionProperty().addListener(new ChangeListener<Throwable>() {
            @Override
            public void changed(ObservableValue<? extends Throwable> observableValue, Throwable throwable, Throwable t1) {
                if (throwable != null) {
                    System.err.println(throwable.getMessage());
                    throwable.printStackTrace();
                }
                if (t1 != null) {
                    System.err.println(t1.getMessage());
                    t1.printStackTrace();
                }
            }
        });
        engine.load(nextUrlString);

    }

    @FXML
    public void load(ActionEvent event) throws Exception {
        if (task != null ) {
            task.get();
        }
        Object source = event.getSource();
        if (source instanceof TextField) {
            TextField address = (TextField)source;
            nextUrlString = address.getText();
        } else if (source instanceof ComboBox) {
            ComboBox bookmark = (ComboBox)source;
            String title = (String)bookmark.getSelectionModel().getSelectedItem();
            nextUrlString = bookmarkLocal.get().getProperty(title);

        }
        File bookmarkFile = new File(APP_DIR, "bookmarks.properties");
        loadBookmarks();
        bookmarkLocal.get().storeToXML(new FileOutputStream(bookmarkFile), "bookmarks");
        engine.load(nextUrlString);
    }

    @FXML
    public void back(ActionEvent event) throws IOException {
        SecHarry.setRoot("main", SecHarry.CSS.UNICHORN);
    }

    @FXML
    public void history(ActionEvent event) throws IOException {
        WebHistory webHistory = engine.getHistory();
        ComboBox comboBox = history;
        int offset =
                comboBox.getSelectionModel().getSelectedIndex()
                        - webHistory.getCurrentIndex();
        webHistory.go(offset);
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
        String masterPW = masterPass.getText();
        if (masterPW != null && !masterPW.isEmpty()) {
            StorePasswdDialog.passwordStoreDialog(masterPW, false);
        }
    }

    @FXML
    public void bookmarkit(ActionEvent event) {
        ComboBox bookmark = bookmarks;
        WebHistory history = engine.getHistory();
        WebHistory.Entry entry = history.getEntries().get(history.getCurrentIndex());
        String key;
        if (entry.getTitle() != null && !entry.getTitle().isEmpty()) {
            key = entry.getTitle();
        } else {
            key = entry.getUrl();
        }
        bookmarkLocal.get().setProperty(key, entry.getUrl());
        bookmark.getItems().add(key);
    }

    private String getBasicAuth(String url) {
        String masterPW = masterPass.getText();
        String base64 = null;
        PasswordManager manager = new PasswordManager(masterPW);
        Tuple<String, String> result = manager.readPassword(url);
        String authString = null;
        if (result != null) {
            authString = String.format("%s:%s", result.getFirst(), result.getSecond());
            base64 = Util.toBase64String(authString.getBytes());
        }
        return base64;
    }

    private void loadBookmarks() {
        try {
            File bookmarkFile = new File(APP_DIR, "bookmarks.properties");
            if (bookmarkFile.exists()) {
                bookmarkLocal.get().loadFromXML(new FileInputStream(bookmarkFile));
                ComboBox bookmarkCombo = bookmarks;
                bookmarkCombo.getItems().addAll(bookmarkLocal.get().keySet());
            }
        } catch (Exception ex) {
            throw new IllegalStateException("loading bookmarks failed....", ex);
        }
    }

    public void setTabContent(Tab tab) throws IOException {
        Parent parent = SecHarry.loadFXML("browserTab", SecHarry.CSS.UNICHORN);
        tab.setContent(parent);
    }

    public void startChecker () throws ExecutionException, InterruptedException {
        task = new HttpsCheckerTask(nextUrlString, ocspCheck.isSelected());
        Platform.runLater(task);
    }

    @Override
    public Scene init() {
        return null;
    }

    public class  HttpsCheckerTask extends Task<Void> {

        private final String url;

        private final boolean ocspCheck;

        public HttpsCheckerTask(String url, boolean ocspCheck) {
            this.url = url;
            this.ocspCheck = ocspCheck;
        }

        @Override
        protected Void call() throws Exception {
            Tuple<Integer, List<X509Certificate>> tuple =
                    HttpsChecker.checkHttpsCertValidity(this.url, ocspCheck, false);
            String text = null;
            if (tuple.getFirst() == 0) {

                if (ocspCheck) {
                    text = "web-site is secure";
                } else {
                    text = "identity checked ok";
                }
            } else if(tuple.getFirst() == -1) {
                text = "WebSite has no validity";
            } else {
                text = "no security info available";
            }
            System.out.println("Try to show alert......");
            status.setText(text);
            return null;
        }
    }

    public static class MyURLStreamHandlerFactory implements URLStreamHandlerFactory {

        public URLStreamHandler createURLStreamHandler(String protocol) {
            System.out.println("Protocol: " + protocol);
            if (protocol.equals("https")) {
                return new URLStreamHandler() {
                    @Override
                    protected URLConnection openConnection(URL u) throws IOException {
                        return ClientFactory.createURLConnection(u);
                    }
                };
            } else if (protocol.equals("http")) {
                    return new URLStreamHandler() {
                        @Override
                        protected URLConnection openConnection(URL u) throws IOException {
                            HttpURLConnection conn = (HttpURLConnection)u.openConnection();
                            return conn;
                        }
                    };
            } else {
                return new URLStreamHandler() {
                    @Override
                    protected URLConnection openConnection(URL u) throws IOException {
                        URLConnection conn = (URLConnection)u.openConnection();
                        return conn;
                    }
                };
            }
        }
    }



}
