package org.harry.security.util.pwdmanager;

import iaik.utils.CryptoUtils;
import org.harry.security.testutils.TestBase;
import org.harry.security.util.SigningUtil;
import org.harry.security.util.TripleDESWrapping;
import org.harry.security.util.Tuple;
import org.junit.Test;

import javax.activation.DataSource;
import java.io.File;
import java.util.Arrays;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertTrue;

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

    @Test
    public void strongEncrypt() throws Exception {
        DataSource ds = PasswordManager.encryptStrong("myPasswd", "masterPW");
        String result = PasswordManager.decryptStrong(ds, "myPasswd", "masterPW");
        assertThat(result,is("myPasswd"));
    }
}
