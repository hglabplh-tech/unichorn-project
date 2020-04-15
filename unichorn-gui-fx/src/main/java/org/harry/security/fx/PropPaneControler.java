package org.harry.security.fx;

import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import org.harry.security.util.ConfigReader;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

public class PropPaneControler implements ControllerInit {

    @FXML private TableView<PropEntry> propTable;

    Properties signingProperties = new Properties();


    public Scene init() {
        propTable.getSelectionModel().setCellSelectionEnabled(true);
        propTable.setEditable(true);

        propTable.getSelectionModel().getSelectedItem();
        signingProperties = ConfigReader.init();
        List<PropEntry> entryList = new ArrayList<>();
        Enumeration names = signingProperties.propertyNames();
        while (names.hasMoreElements()) {
            String key = (String)names.nextElement();
            String value = signingProperties.getProperty(key);
            PropEntry entry = new PropEntry(key, value);
            entryList.add(entry);
        }
        ObservableList<PropEntry> data = propTable.getItems();
        data.clear();
        data.addAll(entryList);


        propTable.getEditingCell();

        propTable.setVisible(false);
        propTable.refresh();
        propTable.setVisible(true);
        return propTable.getScene();
    }

    @FXML
    protected void addRows(ActionEvent event) {

    }


    @FXML
    public void propValueEnter(TableColumn.CellEditEvent<PropEntry, String> event) {
        PropEntry entry = event.getRowValue();
        String newValue = event.getNewValue();
        signingProperties.setProperty(entry.getPropKey(), newValue);

    }

    @FXML
    public void save(ActionEvent event) throws IOException {
        ConfigReader.saveProperties(signingProperties);
        SecHarry.setRoot("main");

    }

    @FXML
    public void cancel(ActionEvent event) throws IOException {
        SecHarry.setRoot("main");

    }
}
