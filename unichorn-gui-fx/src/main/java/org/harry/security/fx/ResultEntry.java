package org.harry.security.fx;

import javafx.beans.property.SimpleStringProperty;

public class ResultEntry {
    private final SimpleStringProperty name = new SimpleStringProperty("");
    private final SimpleStringProperty description = new SimpleStringProperty("");
    private final SimpleStringProperty outcome = new SimpleStringProperty("");


    public ResultEntry() {
        this("","", "");
    }

    public ResultEntry(String name, String description, String outcome) {
        setName(name);
        setDescription(description);
        setOutcome(outcome);
    }

    public String getDescription() {
        return description.get();
    }

    public void setDescription(String fName) {
        description.set(fName);
    }

    public String getOutcome() {
        return outcome.get();
    }

    public void setOutcome(String fName) {
        outcome.set(fName);
    }

    public String getName() {
        return name.get();
    }

    public void setName(String name) {
        this.name.set(name);
    }
}
