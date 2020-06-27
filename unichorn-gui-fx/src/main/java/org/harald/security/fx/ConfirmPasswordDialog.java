package org.harald.security.fx;

import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import org.harry.security.util.SignXAdESUtil;

import java.util.Optional;

/**
 * Class for a Store Password Diialog to store passwords for sites.
 * @author Harald Glab-Plhak
 */
public class ConfirmPasswordDialog {

    /**
     * This method creates and calls the dialog to define a production place of a signature
     * @return the production place definition
     */
    public static String passwordStoreDialog(String user) {
        // Create the custom dialog.
        Dialog<String> dialog = new Dialog<>();
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

        TextField userName = new TextField();
        userName.setPromptText("User");
        userName.setText(user);
        PasswordField password = new PasswordField();
        password.setPromptText("Password");



        grid.add(new Label("User Name:"), 0, 0);
        grid.add(userName, 1, 0);
        grid.add(new Label("Password:"), 0, 1);
        grid.add(password, 1, 1);

// Enable/Disable login button depending on whether a passwordKey was entered.



        dialog.getDialogPane().setContent(grid);

// Request focus on the passwordKey field by default.
        Platform.runLater(() -> password.requestFocus());

// Convert the result to a passwordKey-password-pair when the login button is clicked.
        dialog.setResultConverter(dialogButton -> {
            if (dialogButton == loginButtonType) {
                return password.getText();
            }
            return null;
        });

        Optional<String> result = dialog.showAndWait();

        if (result.isPresent()) {
            return result.get();
        }
        return null;
    }
}
