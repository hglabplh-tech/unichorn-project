package org.harry.security.fx;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;
import org.harry.security.CMSSigner;
import org.harry.security.util.ConfigReader;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.trustlist.TrustListWalkerAndGetter;

import java.io.IOException;
import java.net.URL;
import java.util.List;

/**
 * JavaFX App
 */
public class SecHarry extends Application {

    private static Scene scene;

    public static FXMLLoader fxmlLoader = null;

    @Override
    public void start(Stage stage) throws IOException {
        CMSSigner.setProviders();
        List<TrustListWalkerAndGetter> walkers = ConfigReader.loadAllTrusts();
        SigningBean context = new SigningBean().setWalker(walkers);
        contexts.set(context);
        scene = new Scene(loadFXML("main"));
        stage.setScene(scene);
        stage.show();
    }

    static void setRoot(String fxml) throws IOException {
        scene.setRoot(loadFXML(fxml));
    }



   private static Parent loadFXML(String fxml) throws IOException {
        URL resourceURL = SecHarry.class.getResource(fxml + ".fxml");
        fxmlLoader = new FXMLLoader(resourceURL);
        Pane root = (Pane) fxmlLoader.load();
        ControllerInit controller = (ControllerInit)fxmlLoader.getController();
        Scene scene = controller.init();
        root.getStylesheets().add(SecHarry.class.getResource("/org/harry/security/fx/default.css").toExternalForm());
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

}