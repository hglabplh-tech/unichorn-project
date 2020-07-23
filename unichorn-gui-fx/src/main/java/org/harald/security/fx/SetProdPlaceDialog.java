package org.harald.security.fx;

import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import org.harry.security.util.VerificationResults;

import java.util.Optional;

/**
 * Class for a Store Password Diialog to store passwords for sites.
 * @author Harald Glab-Plhak
 */
public class SetProdPlaceDialog {

    /**
     * This method creates and calls the dialog to define a production place of a signature
     * @return the production place definition
     */
    public static VerificationResults.ProdPlace passwordStoreDialog() {
        // Create the custom dialog.
        Dialog<VerificationResults.ProdPlace> dialog = new Dialog<>();
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

        TextField city = new TextField();
        city.setPromptText("City");
        TextField street = new TextField();
        street.setPromptText("Street");
        TextField zipCode = new TextField();
        zipCode.setPromptText("ZIP Code");
        TextField region = new TextField();
        region.setPromptText("Region");
        TextField country = new TextField();
        country.setPromptText("Region");


        grid.add(new Label("City:"), 0, 0);
        grid.add(city, 1, 0);
        grid.add(new Label("Street:"), 0, 1);
        grid.add(street, 1, 1);
        grid.add(new Label("ZIP Code:"), 0, 2);
        grid.add(zipCode, 1, 2);
        grid.add(new Label("Region:"), 0, 3);
        grid.add(region, 1, 3);
        grid.add(new Label("Country:"), 0, 4);
        grid.add(country, 1, 4);

// Enable/Disable login button depending on whether a passwordKey was entered.



        dialog.getDialogPane().setContent(grid);

// Request focus on the passwordKey field by default.
        Platform.runLater(() -> city.requestFocus());

// Convert the result to a passwordKey-password-pair when the login button is clicked.
        dialog.setResultConverter(dialogButton -> {
            if (dialogButton == loginButtonType) {
                return new VerificationResults.ProdPlace().setCity(city.getText())
                        .setStreet(street.getText())
                        .setZipCode(zipCode.getText())
                        .setRegion(region.getText())
                        .setCountry(country.getText());
            }
            return null;
        });

        Optional<VerificationResults.ProdPlace> result = dialog.showAndWait();

        if (result.isPresent()) {
            return result.get();
        }
        return null;
    }
}
