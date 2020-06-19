package org.harald.security.fx;

import iaik.utils.Util;
import iaik.x509.X509Certificate;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.ListChangeListener;
import javafx.concurrent.Worker;
import javafx.event.ActionEvent;
import javafx.event.Event;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.TabPane.TabClosingPolicy;

import java.io.IOException;
import java.util.UUID;

import static org.harald.security.fx.util.Miscellaneous.getTabPaneByFXID;


public class BrowserCtrl implements ControllerInit {

    @FXML private ProgressBar progress;
    @FXML private TabPane browserPane;
    @Override
    public Scene init() {
        return null;
    }

    public void setTabContent(Tab tab) throws IOException {
        Parent parent = SecHarry.loadFXML("browserTab", SecHarry.CSS.UNICHORN);
        tab.setContent(parent);
    }

    @FXML
    public void addtab(ActionEvent event) throws IOException {
        TabPane.TabClosingPolicy policy = TabPane.TabClosingPolicy.SELECTED_TAB;
        Tab newTab = new Tab();
        String id = UUID.randomUUID().toString();
        newTab.setId(id);
        newTab.setClosable(true);
        newTab.setText("search tab");
        setTabContent(newTab);
        browserPane.getTabs().add(newTab);
    }


}
