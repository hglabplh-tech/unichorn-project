package org.harald.security.fx;

import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.*;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.concurrent.Worker;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebEvent;
import javafx.scene.web.WebHistory;
import javafx.scene.web.WebView;
import org.harry.security.util.HttpsChecker;
import org.harry.security.util.ServerInfoGetter;
import org.harry.security.util.Tuple;
import org.harry.security.util.ocsp.HttpOCSPClient;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PrivateKey;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;

import static org.harald.security.fx.util.Miscellaneous.*;
import static org.harry.security.CommonConst.OCSP_URL;
import static org.harry.security.util.HttpsChecker.loadKey;

public class BrowserCtrl implements ControllerInit {

    private ProgressBar progress;
    WebEngine engine = null;
    String nextUrl = "https://www.google.de";
    int webIndex = 0;
    @Override
    public Scene init() {
        WebView webViewer = getWebViewByFXID("browser");
        engine = webViewer.getEngine();
        progress = getProgessBarByFXID("progress");


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




        engine.getLoadWorker().exceptionProperty().addListener(new ChangeListener<Throwable>() {
            @Override
            public void changed(ObservableValue<? extends Throwable> arg0, Throwable arg1, Throwable arg2) {
                System.out.println(arg0);
                System.out.println(arg1);
                System.out.println(arg2);
            }
        });
        worker.stateProperty().addListener(new ChangeListener<Worker.State>() {
            @Override
            public void changed(ObservableValue<? extends Worker.State> observable, Worker.State oldValue, Worker.State newValue) {
                TextField address = getTextFieldByFXID("address");
                CheckBox ocspCheck = getCheckBoxByFXID("ocspCheck");
                nextUrl = engine.getLocation();
                address.setText(nextUrl);

                if (newValue == Worker.State.SUCCEEDED) {
                    // hide progress bar then page is ready
                    progress.setVisible(false);
                }
                else if (newValue == Worker.State.SCHEDULED) {
                    Label label = getLabelByFXID("status");
                    URL url = null;
                    try {
                        url = new URL(nextUrl);
                    } catch (MalformedURLException e) {
                        e.printStackTrace();
                    }
                    int port = 443;
                    if (url.getPort() != -1) {
                        port = url.getPort();
                    }
                    try {
                        if (nextUrl.startsWith("https") && !url.getHost().equals("localhost")) {
                            Tuple<Integer, List<X509Certificate>> tuple =
                                    HttpsChecker.checkHttpsCertValidity(nextUrl, ocspCheck.isSelected(), false);
                            if (tuple.getFirst() == 0) {
                                if (ocspCheck.isSelected()) {
                                    label.setText("web-site is secure");
                                } else {
                                    label.setText("identity checked ok");
                                }
                            } else {
                                label.setText("no security info available");
                            }
                     /*       PrintWriter writer = new PrintWriter(System.out);
                            ServerInfoGetter getter =
                                    new ServerInfoGetter(url.getHost(), port,
                                            writer, "");
                            Hashtable<X509Certificate, X509Certificate[]> certsTable =
                                    getter.getInformation();
                            Enumeration<X509Certificate[]> elements = certsTable.elements();
                            if (elements.hasMoreElements()) {
                                iaik.x509.X509Certificate[] iaikVersions = Util.convertCertificateChain(elements.nextElement());
                                ocspCheck(OCSP_URL, iaikVersions);
                            } */

                        }
                    } catch (Exception ex) {
                        throw new IllegalStateException("cannot load it", ex);
                    }
                }


            }
        });
        engine.load(nextUrl);
        return webViewer.getScene();
    }

    @FXML
    public void load(ActionEvent event) {
        TextField address = getTextFieldByFXID("address");
        nextUrl = address.getText();
        engine.load(nextUrl);
    }

    @FXML
    public void back(ActionEvent event) throws IOException {
        SecHarry.setRoot("main", SecHarry.CSS.UNICHORN);
    }

    @FXML
    public void backward(ActionEvent event) throws IOException {
        WebHistory history = engine.getHistory();
        if (webIndex < 0) {
            String url = history.getEntries().get(0).getUrl();
            nextUrl = url;
            engine.load(nextUrl);
            progress.progressProperty().bind(engine.getLoadWorker().progressProperty());
            progress.setVisible(true);
        } else if (webIndex == history.getEntries().size()) {
            String url = history.getEntries().get(webIndex -1).getUrl();
            nextUrl = url;
            engine.load(nextUrl);
            progress.progressProperty().bind(engine.getLoadWorker().progressProperty());
            progress.setVisible(true);
            webIndex--;
        } else {
            String url = history.getEntries().get(webIndex).getUrl();
            nextUrl = url;
            engine.load(nextUrl);
            progress.progressProperty().bind(engine.getLoadWorker().progressProperty());
            progress.setVisible(true);
            webIndex--;
        }
    }

    @FXML
    public void forward(ActionEvent event) throws IOException {

        WebHistory history = engine.getHistory();
        if (webIndex <= 0) {
            String url = history.getEntries().get(0).getUrl();
            nextUrl = url;
            engine.load(nextUrl);
            progress.progressProperty().bind(engine.getLoadWorker().progressProperty());
            progress.setVisible(true);
            webIndex++;
        } else if (webIndex == history.getEntries().size()) {
            String url = history.getEntries().get(webIndex -1).getUrl();
            nextUrl = url;
            engine.load(nextUrl);
            progress.progressProperty().bind(engine.getLoadWorker().progressProperty());
            progress.setVisible(true);
            webIndex++;
        } else {
            String url = history.getEntries().get(webIndex).getUrl();
            nextUrl = url;
            engine.load(nextUrl);
            progress.progressProperty().bind(engine.getLoadWorker().progressProperty());
            progress.setVisible(true);
            webIndex++;
        }
    }



}
