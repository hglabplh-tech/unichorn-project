package org.harald.security.fx;

import javafx.beans.property.SimpleStringProperty;

public class PasswdEntry {
    private final SimpleStringProperty propKey = new SimpleStringProperty("");
    private final SimpleStringProperty propUser = new SimpleStringProperty("");
    private final SimpleStringProperty propPasswd = new SimpleStringProperty("");


    public PasswdEntry() {
        this("", "", "");
    }

    public PasswdEntry(String propKey, String propUser, String propPasswd) {
        setPropKey(propKey);
        setPropUser(propUser);
        setPropPasswd(propPasswd);
    }

    public String getPropKey() {
        return propKey.get();
    }

    public void setPropKey(String fName) {
        propKey.set(fName);
    }

    public String getPropUser() {
        return propUser.get();
    }

    public void setPropUser(String fName) {
        propUser.set(fName);
    }

    public String getPropPasswd() {
        return propPasswd.get();
    }

    public void setPropPasswd(String fName) {
        propPasswd.set(fName);
    }


}
