package org.harry.security.util;

import org.harry.security.testutils.TestBase;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.trustlist.TrustListLoader;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;

public class CertificateWizzardTest extends TestBase {

    @Test
    public void testChainOk() throws IOException {
        ConfigReader.MainProperties properties = ConfigReader.loadStore();
        properties.setKeystorePass("geheim");

        CertificateWizzard wizzard = new CertificateWizzard(properties);
        KeyPair caKeys = wizzard.generateCA(properties.getCommonName(), true);
        KeyPair interKeys = wizzard.generateIntermediate(caKeys, properties.getCommonName(), true);
        wizzard.generateUser(interKeys, properties.getCommonName(), true);
        File tempStore = File.createTempFile("keyStore", ".jks");
        FileOutputStream stream = new FileOutputStream(tempStore);
        File tempTrust = File.createTempFile("trust", ".xml");
        FileOutputStream trustStream = new FileOutputStream(tempTrust);
        KeyStoreTool.storeKeyStore(wizzard.getStore(), stream, properties.getKeystorePass().toCharArray());
        TrustListLoader loader = wizzard.getLoader();
        loader.storeTrust(trustStream);
    }
}
