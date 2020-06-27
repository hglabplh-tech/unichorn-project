package org.harald.security.fx;

import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import org.harry.security.util.SignXAdESUtil;
import org.harry.security.util.Tuple;

import java.util.Optional;

/**
 * Class for a Store Password Diialog to store passwords for sites.
 * @author Harald Glab-Plhak
 */
public class NewEmailAccountDialog {

    /**
     * This method creates and calls the dialog to define a production place of a signature
     * @return the production place definition
     */
    public static Tuple<String, Tuple<String, String>> createAccountDialog() {
        // Create the custom dialog.
        Dialog<Tuple<String, Tuple<String, String>>> dialog = new Dialog<>();
        dialog.setTitle("Define Production Place for Signature");

// Set the icon (must be included in the project).
       // dialog.setGraphic(new ImageView(this.getClass().getResource("login.png").toString()));

// Set the button types.
        ButtonType loginButtonType = new ButtonType("Give Back Prod Place", ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(loginButtonType, ButtonType.CANCEL);

// Create the passwordKey and password labels and fields.
        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(20, 150, 10, 10));

        TextField emailAddress = new TextField();
        emailAddress.setPromptText("e-mail");

        TextField password = new TextField();
        password.setPromptText("password");

        TextField providerName = new TextField();
        providerName.setPromptText("password");




        grid.add(new Label("E-Mail-Address:"), 0, 0);
        grid.add(emailAddress, 1, 0);
        grid.add(new Label("Password:"), 0, 1);
        grid.add(password, 1, 1);
        grid.add(new Label("Provider Name:"), 0, 2);
        grid.add(providerName, 1, 2);




// Enable/Disable login button depending on whether a passwordKey was entered.



        dialog.getDialogPane().setContent(grid);

// Request focus on the passwordKey field by default.
        Platform.runLater(() -> emailAddress.requestFocus());

// Convert the result to a passwordKey-password-pair when the login button is clicked.
        dialog.setResultConverter(dialogButton -> {
            if (dialogButton == loginButtonType) {
                return new Tuple<>(providerName.getText(), new Tuple<>(emailAddress.getText(), password.getText()));
            }
            return null;
        });

        Optional<Tuple<String, Tuple<String, String>>> result = dialog.showAndWait();

        if (result.isPresent()) {
            return result.get();
        }
        return null;
    }
}
