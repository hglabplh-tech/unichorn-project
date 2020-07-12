package org.harald.security.fx;

import iaik.x509.X509Certificate;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import org.harry.security.util.Tuple;

import java.util.Optional;

/**
 * Class for a Store Password Diialog to store passwords for sites.
 * @author Harald Glab-Plhak
 */
public class ShowCertsDialog {

    /**
     * This method creates and calls the dialog to define a production place of a signature
     * @param chain the certificate chain
     *
     */
    public static void showCertChainDialog(X509Certificate[] chain) {
        // Create the custom dialog.
        Dialog<Void> dialog = new Dialog<>();
        dialog.setTitle("Define Production Place for Signature");

// Set the icon (must be included in the project).
       // dialog.setGraphic(new ImageView(this.getClass().getResource("login.png").toString()));

// Set the button types.
        ButtonType loginButtonType = new ButtonType("OK", ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(loginButtonType, ButtonType.CANCEL);

// Create the passwordKey and password labels and fields.
        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(20, 150, 10, 10));

        TextArea certs = new TextArea();
        StringBuffer buffer = new StringBuffer();
        for (X509Certificate cert: chain) {
            buffer.append(cert.toString(true));
            buffer.append("\n=================================================================\n");
        }
        certs.setText(buffer.toString());


        grid.add(certs, 0, 0);
// Enable/Disable login button depending on whether a passwordKey was entered.



        dialog.getDialogPane().setContent(grid);

// Request focus on the passwordKey field by default.
        Platform.runLater(() -> certs.requestFocus());

// Convert the result to a passwordKey-password-pair when the login button is clicked.

        dialog.showAndWait();


        return;
    }
}
