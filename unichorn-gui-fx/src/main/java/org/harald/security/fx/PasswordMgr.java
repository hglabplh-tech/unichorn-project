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

/**
 * JavaFX App
 */
public class PasswordMgr extends Application {

    private static Scene scene;

    public static FXMLLoader fxmlLoader = null;

    @Override
    public void start(Stage stage) throws IOException {
        CMSSigner.setProviders();
        scene = new Scene(loadFXML("passwdmgr", CSS.UNICHORN));
        stage.setScene(scene);
        stage.show();
    }

    static void setRoot(String fxml, CSS css) throws IOException {
        scene.setRoot(loadFXML(fxml, css));
}



    private static Parent loadFXML(String fxml, CSS css) throws IOException {
        URL resourceURL = PasswordMgr.class.getResource(fxml + ".fxml");
        fxmlLoader = new FXMLLoader(resourceURL);
        Pane root = (Pane) fxmlLoader.load();
        root.setMinSize(1200.0, 700.0);
        ControllerInit controller = (ControllerInit)fxmlLoader.getController();
        if (root.getStylesheets().size() > 0) {
            root.getStylesheets().remove(0);
        }
       root.getStylesheets().add(css.getUrl());

        Scene scene = controller.init();
        if (scene != null) {

        }

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
        ABBY(PasswordMgr.class.getResource("/org/harald/security/fx/abby.css").toExternalForm()),
        UNICHORN(PasswordMgr.class.getResource("/org/harald/security/fx/unichorn.css").toExternalForm()),
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