package org.harald.security.fx;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;
import org.harry.security.CMSSigner;
import org.harry.security.util.CertificateWizzard;
import org.harry.security.util.ConfigReader;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.trustlist.TrustListManager;

import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.Properties;

/**
 * JavaFX App
 */
public class SecHarry extends Application {

    private static Scene scene;

    public static FXMLLoader fxmlLoader = null;

    public static ThreadLocal<Properties> bookmarkLocal = null;

    @Override
    public void start(Stage stage) throws IOException {
        CMSSigner.setProviders();
        CertificateWizzard.initThis();
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        SigningBean context = new SigningBean().setWalker(walkers);
        contexts.set(context);
        scene = new Scene(loadFXML("main", CSS.UNICHORN));
        stage.setScene(scene);
        synchronized (SecHarry.class)  {
            if (bookmarkLocal == null) {
                bookmarkLocal = new ThreadLocal<>();
                bookmarkLocal.set(new Properties());
            }
        }
        stage.show();
    }

    public static void setRoot(String fxml, CSS css) throws IOException {
        scene.setRoot(loadFXML(fxml, css));
}



    public static Parent loadFXML(String fxml, CSS css) throws IOException {
        URL resourceURL = SecHarry.class.getResource(fxml + ".fxml");
        fxmlLoader = new FXMLLoader(resourceURL);
        Pane root = (Pane) fxmlLoader.load();
        root.setMinSize(1200.0, 700.0);
        ControllerInit controller = (ControllerInit)fxmlLoader.getController();
        if (root.getStylesheets().size() > 0) {
            root.getStylesheets().remove(0);
        }
       root.getStylesheets().add(css.getUrl());
        controller.init();


        return root;
    }




    public static void main(String[] args) {
        launch();
    }

    public  static final ThreadLocal<SigningBean> contexts = new ThreadLocal<>();

    public static SigningBean getContext() {
        return contexts.get(); // get returns the variable unique to this thread
    }

    public void doGet(SigningBean context) {

        contexts.set(context); // save that context to our thread-local - other threads
        // making this call don't overwrite ours
        try {
            // business logic
        } finally {
            contexts.remove(); // 'ensure' removal of thread-local variable
        }
    }

    public static enum CSS {
        ABBY(SecHarry.class.getResource("/org/harald/security/fx/abby.css").toExternalForm()),
        UNICHORN(SecHarry.class.getResource("/org/harald/security/fx/unichorn.css").toExternalForm()),
        ;



        private String url;

        CSS(String url) {
            this.url = url;
        }

        public String getUrl() {
            return url;
        }
    }

}