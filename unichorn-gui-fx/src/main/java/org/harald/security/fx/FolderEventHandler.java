package org.harald.security.fx;

import com.sun.mail.imap.IMAPFolder;
import javafx.event.Event;
import javafx.event.EventHandler;
import javafx.scene.control.ListView;
import org.harry.security.util.Tuple;
import org.harry.security.util.mailer.EReceiver;
import org.pmw.tinylog.Logger;

import javax.mail.Address;
import javax.mail.Folder;
import javax.mail.Message;
import javax.mail.Store;
import java.util.ArrayList;
import java.util.List;

import static org.harald.security.fx.util.Miscellaneous.getPrivateKeyTuple;

public class FolderEventHandler<ActionEvent> implements EventHandler {

    private final IMAPFolder imapFolder;

    private final Store store;

    private final ListView<String> listView;

    private List<String> mailEntries = new ArrayList<>();

    public FolderEventHandler(Store store, Folder folder, ListView<String> listView) {
        this.imapFolder = (IMAPFolder) folder;
        this.store = store;
        this.listView = listView;
    }

    @Override
    public void handle(Event event)  {

        try {
            EReceiver receiver = new EReceiver(new Tuple<Store,Folder>(store, imapFolder), getPrivateKeyTuple());
            Message[] messages = new Message[0];
            messages = receiver.receiveMails("dummy");
            for (Message msg : messages) {
                Address[] from = msg.getFrom();
                StringBuffer buf = new StringBuffer();
                for (Address addr : from) {
                    buf.append(addr.toString() + " , ");
                }
                mailEntries.add(msg.getSubject() + ";;" + buf.toString());
            }
            listView.getItems().clear();
            listView.getItems().addAll(mailEntries);
        } catch (Exception ex) {
            Logger.trace(" cannot load entries: " + ex.getMessage());
            Logger.trace(ex);
            throw new IllegalStateException(" cannot load entries", ex);
        }
    }
}
