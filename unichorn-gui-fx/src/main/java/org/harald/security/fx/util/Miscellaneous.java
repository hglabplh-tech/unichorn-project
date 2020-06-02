package org.harald.security.fx.util;

import javafx.event.ActionEvent;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.web.WebView;
import javafx.stage.FileChooser;
import javafx.stage.Window;
import org.harald.security.fx.SecHarry;

import java.io.File;

public class Miscellaneous {
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static TextField getTextFieldByFXID(String fxId) {
        TextField inputField = (TextField) SecHarry.fxmlLoader.getNamespace().get(fxId);
        return inputField;
    }

    public static Label getLabelByFXID(String fxId) {
        Label inputField = (Label) SecHarry.fxmlLoader.getNamespace().get(fxId);
        return inputField;
    }

    public static ChoiceBox getChoiceBoxByFXID(String fxId)  {
        ChoiceBox choice = (ChoiceBox) SecHarry.fxmlLoader.getNamespace().get(fxId);
        return choice;
    }

    public static ComboBox getComboBoxByFXID(String fxId)  {
        ComboBox choice = (ComboBox) SecHarry.fxmlLoader.getNamespace().get(fxId);
        return choice;
    }

    public static TextArea getTextAreaByFXID(String fxId)  {
        TextArea choice = (TextArea) SecHarry.fxmlLoader.getNamespace().get(fxId);
        return choice;
    }

    public static WebView getWebViewByFXID(String fxId)  {
        WebView choice = (WebView) SecHarry.fxmlLoader.getNamespace().get(fxId);
        return choice;
    }

    public static CheckBox getCheckBoxByFXID(String fxId)  {
        CheckBox check = (CheckBox) SecHarry.fxmlLoader.getNamespace().get(fxId);
        return check;
    }

    public static ProgressBar getProgessBarByFXID(String fxId)  {
        ProgressBar progress = (ProgressBar) SecHarry.fxmlLoader.getNamespace().get(fxId);
        return progress;
    }

    public static ListView getListViewByFXID(String fxId) {
        ListView inputField = (ListView) SecHarry.fxmlLoader.getNamespace().get(fxId);
        return inputField;
    }
    public static File showOpenDialog(ActionEvent event, String fxId) {
        FileChooser fDialog = new FileChooser();
        fDialog.setTitle("Select Path");
        File currentDir = new File(System.getProperty("user.home", "C:\\")).getAbsoluteFile();

        fDialog.setInitialDirectory(currentDir);
        Window parent = ((MenuItem)event.getTarget()).getParentPopup().getOwnerWindow();
        File file = fDialog.showOpenDialog(parent);
        if (file != null) {
            TextField inputField = getTextFieldByFXID(fxId);
            if (inputField != null) {
                inputField.setText(file.getAbsolutePath());
                return file;
            }
        }
        return null;
    }

    public static File showSaveDialog(ActionEvent event, String fxId) {
        FileChooser fDialog = new FileChooser();
        fDialog.setTitle("Select Path");
        File currentDir = new File(System.getProperty("user.home", "C:\\")).getAbsoluteFile();

        fDialog.setInitialDirectory(currentDir);
        Window parent = ((MenuItem)event.getTarget()).getParentPopup().getOwnerWindow();
        File file = fDialog.showSaveDialog(parent);
        if (file != null) {
            TextField inputField = getTextFieldByFXID(fxId);
            if (inputField != null) {
                inputField.setText(file.getAbsolutePath());
                return file;

            }
        }
        return null;
    }

    public static File showSaveDialogFromButton(ActionEvent event, String fxId) {
        FileChooser fDialog = new FileChooser();
        fDialog.setTitle("Select Path");
        File currentDir = new File(System.getProperty("user.home", "C:\\")).getAbsoluteFile();

        fDialog.setInitialDirectory(currentDir);
        Window parent = ((Node)event.getTarget()).getScene().getWindow();
        File file = fDialog.showSaveDialog(parent);
        if (file != null) {
            if (fxId != null) {
                TextField inputField = getTextFieldByFXID(fxId);
                if (inputField != null) {
                    inputField.setText(file.getAbsolutePath());
                }
            }
            return file;
        }
        return null;
    }


}
