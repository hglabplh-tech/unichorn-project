package org.harald.security.fx;

import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.util.Pair;
import org.harry.security.util.Tuple;
import org.harry.security.util.pwdmanager.PasswordManager;

import java.util.Optional;
import java.util.TooManyListenersException;

/**
 * Class for a Store Password Diialog to store passwords for sites.
 * @author Harald Glab-Plhak
 */
public class StorePasswdDialog {

    /**
     * This method creates and calls the dialog to store the password.
     * The password is then stored in the application directories password.properties file (encrypted)
     * @param masterPW the master password
     * @return the dialog object
     */
    public static Dialog<Tuple<String, Pair<String, String>>> passwordStoreDialog(String masterPW, boolean generate) {
        // Create the custom dialog.
        Dialog<Tuple<String, Pair<String, String>>> dialog = new Dialog<>();
        dialog.setTitle("Store password Dialog");
        dialog.setHeaderText("Store passwords for sites");

// Set the icon (must be included in the project).
       // dialog.setGraphic(new ImageView(this.getClass().getResource("login.png").toString()));

// Set the button types.
        ButtonType loginButtonType = new ButtonType("Store Passwd", ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(loginButtonType, ButtonType.CANCEL);

// Create the passwordKey and password labels and fields.
        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(20, 150, 10, 10));

        TextField passwordKey = new TextField();
        passwordKey.setPromptText("Password Key");
        TextField userName = new TextField();
        userName.setPromptText("UserName");
        PasswordField password = new PasswordField();
        password.setPromptText("Password");

        grid.add(new Label("Password Key:"), 0, 0);
        grid.add(passwordKey, 1, 0);
        grid.add(new Label("User Name:"), 0, 1);
        grid.add(userName, 1, 1);
        grid.add(new Label("Password:"), 0, 2);
        grid.add(password, 1, 2);

// Enable/Disable login button depending on whether a passwordKey was entered.
        Node loginButton = dialog.getDialogPane().lookupButton(loginButtonType);
        PasswordManager manager = new PasswordManager(masterPW);
        if (generate) {
            String newPW = manager.generatePass();
            password.setText(newPW);
        }

// Do some validation (using the Java 8 lambda syntax).
        passwordKey.textProperty().addListener((observable, oldValue, newValue) -> {
            loginButton.setDisable(newValue.trim().isEmpty());
        });

        dialog.getDialogPane().setContent(grid);

// Request focus on the passwordKey field by default.
        Platform.runLater(() -> passwordKey.requestFocus());

// Convert the result to a passwordKey-password-pair when the login button is clicked.
        dialog.setResultConverter(dialogButton -> {
            if (dialogButton == loginButtonType) {
                return new Tuple<String, Pair<String, String>>(passwordKey.getText(),
                        new Pair<>(userName.getText(), password.getText()));
            }
            return null;
        });

        Optional<Tuple<String, Pair<String, String>>> result = dialog.showAndWait();

        result.ifPresent(keyPassword -> {
            System.out.println("PasswordKey=" + keyPassword.getFirst() + "UserName" + keyPassword.getSecond().getKey() + ", Password=" + keyPassword.getSecond().getValue());
        });
        if (result.isPresent()) {

            manager.storePassword(result.get().getFirst(),
                    result.get().getSecond().getKey(),
                    result.get().getSecond().getValue());
        }
        return dialog;
    }
}
