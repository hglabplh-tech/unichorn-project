package org.harry.security.util.pwdmanager;

import org.harry.security.testutils.TestBase;
import org.harry.security.util.Tuple;
import org.junit.Test;

import java.io.File;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class PasswordManagerTest extends TestBase {

    @Test
    public void writeReadPasswordOk() throws Exception{
        File pwdStore = File.createTempFile("pwdstor", ".properties");
        pwdStore.delete();
        PasswordManager manager = new PasswordManager("topSecret", pwdStore);
        manager.storePassword("https://localhost/manager/html", "Benutzer","strengGeheim");
        assertThat(pwdStore.exists(), is(true));
        Tuple<String, String> result = manager.readPassword("https://localhost/manager/html");
        assertThat(result.getFirst(), is("Benutzer"));
        assertThat(result.getSecond(), is("strengGeheim"));
    }
}
