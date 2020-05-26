package org.harry.security.util;

import iaik.x509.X509Certificate;
import iaik.x509.attr.AttributeCertificate;
import org.harry.security.testutils.TestBase;
import org.harry.security.util.bean.AttrCertBean;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.trustlist.TrustListLoader;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.CoreMatchers.is;


public class CertificateWizzardTest extends TestBase {

    @Test
    public void testChainOk() throws IOException {
        ConfigReader.MainProperties properties = ConfigReader.loadStore();
        properties.setKeystorePass("geheim");

        FileOutputStream streamOut = new FileOutputStream(properties.getAttrCertPath());
        CertificateWizzard wizzard = new CertificateWizzard(properties, streamOut);
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

    @Test
    public void createAttributeCert() {
        String[] targetnames = new String[]{"Unichorn Team 1", "Unichorn Team 2", "Unichorn Team 3", "Unichorn Team 4"};
        AttrCertBean attrBean = new AttrCertBean()
        .setRoleName("urn:signer")
        .setCommonName("Common Signer Author")
        .setTargetName("Unichorn Signer")
        .setTargetNames(targetnames)
        .setTargetGroup("Unichorn Signing Group")
        .setAuthCountry("DE")
        .setAuthOrganization("Unichorn Signing GmbH")
        .setAuthOrganizationalUnit("Unichorn Signing Development Team")
        .setAuthCommonName("Unichorn Signers Group")
        .setCategory("signing")
        .setAccessIdentityService("www.unichorn-signing.de")
        .setAccessIdentityIdent("signingId")
        .setGroupValue1("Developers Certificates 1")
        .setGroupValue2("Developers Certificates 2");
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        AttributeCertificate attrCert = CertificateWizzard.createAttributeCertificate(keys.getSecond()[0],
                keys.getSecond()[0],
                keys.getFirst(),
                attrBean);
        assertThat(attrCert, is(notNullValue()));

    }
}
