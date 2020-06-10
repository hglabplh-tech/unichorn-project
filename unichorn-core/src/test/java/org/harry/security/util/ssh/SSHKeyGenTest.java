package org.harry.security.util.ssh;

import com.jcraft.jsch.KeyPair;
import org.junit.Test;

import java.io.File;

public class SSHKeyGenTest {

    @Test
    public void generateKeysTest() throws Exception {
        File file = File.createTempFile("keys_ssh", "_priv_");
        file.delete();
        SSHKeyGen.generateKeyPair(SSHKeyGen.KeyPairType.RSA, "passaworta", file.getAbsolutePath());
    }
}
