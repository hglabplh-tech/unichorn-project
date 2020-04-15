package org.harry.security.fx;

import javafx.beans.property.SimpleStringProperty;

public class PropEntry {
    private final SimpleStringProperty propKey = new SimpleStringProperty("");
    private final SimpleStringProperty propValue = new SimpleStringProperty("");


    public PropEntry() {
        this("", "");
    }

    public PropEntry(String propKey, String propValue) {
        setPropKey(propKey);
        setPropValue(propValue);
    }

    public String getPropKey() {
        return propKey.get();
    }

    public void setPropKey(String fName) {
        propKey.set(fName);
    }

    public String getPropValue() {
        return propValue.get();
    }

    public void setPropValue(String fName) {
        propValue.set(fName);
    }


}
