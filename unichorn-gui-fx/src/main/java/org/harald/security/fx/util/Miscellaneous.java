package org.harald.security.fx.util;

import iaik.pkcs.pkcs11.Session;
import iaik.x509.X509Certificate;
import javafx.event.ActionEvent;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.web.WebView;
import javafx.stage.FileChooser;
import javafx.stage.Window;
import org.harald.security.fx.EMailCenterCtrl;
import org.harald.security.fx.SecHarry;
import org.harry.security.pkcs11.CardManager;
import org.harry.security.util.Tuple;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.mailer.EmailClientConfiguration;
import security.harry.org.emailer_client._1.ClientConfig;
import security.harry.org.emailer_client._1.CryptoConfigType;

import javax.mail.Message;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class Miscellaneous {
    public  static final ThreadLocal<ThreadBean> contexts = new ThreadLocal<>();
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

    public static Tab getTabByFXID(String fxId) {
        Tab tab = (Tab) SecHarry.fxmlLoader.getNamespace().get(fxId);
        return tab;
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

    public static TabPane getTabPaneByFXID(String fxId)  {
        TabPane pane = (TabPane) SecHarry.fxmlLoader.getNamespace().get(fxId);
        return pane;
    }

    public static ProgressBar getProgessBarByFXID(String fxId)  {
        ProgressBar progress = (ProgressBar) SecHarry.fxmlLoader.getNamespace().get(fxId);
        return progress;
    }

    public static ListView getListViewByFXID(String fxId) {
        ListView inputField = (ListView) SecHarry.fxmlLoader.getNamespace().get(fxId);
        return inputField;
    }

    public static File showOpenDialog(ActionEvent event, TextField field) {
        FileChooser fDialog = new FileChooser();
        fDialog.setTitle("Select Path");
        File currentDir = new File(System.getProperty("user.home", "C:\\")).getAbsoluteFile();

        fDialog.setInitialDirectory(currentDir);
        Window parent = ((MenuItem)event.getTarget()).getParentPopup().getOwnerWindow();
        File file = fDialog.showOpenDialog(parent);
        if (file != null) {
            TextField inputField = field;
            if (inputField != null) {
                inputField.setText(file.getAbsolutePath());
                return file;
            }
        }
        return null;
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

    public static File showSaveDialog(ActionEvent event, TextField input) {
        FileChooser fDialog = new FileChooser();
        fDialog.setTitle("Select Path");
        File currentDir = new File(System.getProperty("user.home", "C:\\")).getAbsoluteFile();

        fDialog.setInitialDirectory(currentDir);
        Window parent = ((MenuItem)event.getTarget()).getParentPopup().getOwnerWindow();
        File file = fDialog.showSaveDialog(parent);
        if (file != null) {
            TextField inputField = input;
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

    public static File showOpenDialogButton(ActionEvent event, ListView<String> list) {
        FileChooser fDialog = new FileChooser();
        fDialog.setTitle("Select Path");
        File currentDir = new File(System.getProperty("user.home", "C:\\")).getAbsoluteFile();

        fDialog.setInitialDirectory(currentDir);
        Window parent = ((Node)event.getTarget()).getScene().getWindow();
        File file = fDialog.showOpenDialog(parent);
        if (file != null) {
            if (list != null) {
                list.getItems().add(file.getAbsolutePath());
            }
            return file;
        }
        return null;
    }


    public static Tuple<PrivateKey, X509Certificate[]> getPrivateKeyTuple() throws Exception {
        Tuple<PrivateKey, X509Certificate[]> stored = contexts.get().getEmailKeys();
        Tuple<String, String> confPassword = EMailCenterCtrl.getEMailPasswd("emailCryptoConf");
        ClientConfig clientConfig = EmailClientConfiguration.loadClientConf(confPassword.getSecond());
        String name = clientConfig.getCryptoConfigName();
        Optional<CryptoConfigType> cryptoOpt = clientConfig
                .getCryptoConfig()
                .stream().filter(e -> e.getName().equals(name))
                .findFirst();
        if (cryptoOpt.isPresent() && stored == null) {
            CryptoConfigType cryptoConf = cryptoOpt.get();
            if (cryptoConf.getKeyStoreFile().equals("::SMARTCARD::")) {
                String pin = cryptoConf.getPassword();
                CardManager manager = new CardManager();
                manager.readCardData(pin);
                manager.getKeyStore(pin);
                X509Certificate signerCert = manager.getSignerCertificate_();
                X509Certificate[] chain = new X509Certificate[1];
                chain[0] = signerCert;
                Tuple<PrivateKey, X509Certificate[]> result = new Tuple<>(manager.getSignatureKey_(), chain);
                contexts.get().setEmailKeys(result);
                return result;
            } else {
                File keyStoreFile = new File(cryptoConf.getKeyStoreFile());
                KeyStore keystore = KeyStoreTool.loadStore(
                        new FileInputStream(keyStoreFile),
                        cryptoConf.getPassword().toCharArray(), "PKCS12");
                Tuple<PrivateKey, X509Certificate[]> result = KeyStoreTool.getKeyEntry(keystore,
                        cryptoConf.getAlias(), cryptoConf.getPassword().toCharArray());
                contexts.get().setEmailKeys(result);
                return result;
            }
        } else if (stored != null) {
            return stored;
        } else {
            throw new IllegalStateException("unable to select crypto-config");
        }
    }

    public static ThreadBean getContext() {
        return contexts.get(); // get returns the variable unique to this thread
    }

    public static class ThreadBean {
        private boolean foreward = false;
        private Message orgForReplyMsg = null;
        private SigningBean bean = null;
        private Session session = null;
        private List<String> toAddresses = new ArrayList<>();
        private Tuple<PrivateKey, X509Certificate[]> emailKeys = null;

        public SigningBean getBean() {
            return bean;
        }

        public ThreadBean setBean(SigningBean bean) {
            this.bean = bean;
            return this;
        }

        public Session getSession() {
            return session;
        }

        public ThreadBean setSession(Session session) {
            this.session = session;
            return this;
        }

        public Tuple<PrivateKey, X509Certificate[]> getEmailKeys() {
            return emailKeys;
        }

        public ThreadBean setEmailKeys(Tuple<PrivateKey, X509Certificate[]> emailKeys) {
            this.emailKeys = emailKeys;
            return this;
        }

        public List<String> getToAddresses() {
            return toAddresses;
        }

        public ThreadBean setToAddresses(List<String> toAddresses) {
            this.toAddresses = toAddresses;
            return this;
        }

        public Message getOrgForReplyMsg() {
            return orgForReplyMsg;
        }

        public ThreadBean setOrgForReplyMsg(Message orgForReplyMsg) {
            this.orgForReplyMsg = orgForReplyMsg;
            return this;
        }

        public boolean isForeward() {
            return foreward;
        }

        public ThreadBean setForeward(boolean foreward) {
            this.foreward = foreward;
            return this;
        }
    }
}
