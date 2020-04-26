package org.harry.security.util.crlext;

import iaik.x509.X509Certificate;
import org.etsi.uri._02231.v2_.TrustStatusListType;
import org.harry.security.testutils.TestBase;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.trustlist.TrustListLoader;
import org.harry.security.util.trustlist.TrustListManager;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;


import java.security.KeyStore;
import java.security.PrivateKey;

import static org.junit.Assert.assertNotNull;

public class CRLEditTest extends TestBase {

    private static final String ALIAS = "Common T-Systems Green TeamUserRSA";

    @Test
    public void loadAndChange() throws Exception {
        InputStream keyStore = CRLEditTest.class.getResourceAsStream("/certificates/application.jks");
        assertNotNull(keyStore);
        KeyStore store = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "JKS");
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getKeyEntry(store, ALIAS, "geheim".toCharArray());
        InputStream stream = CRLEditTest.class.getResourceAsStream("/crl/unichorn.crl");
        InputStream certIN = CRLEditTest.class.getResourceAsStream("/certificates/hgp.cer");
        X509Certificate hgpCert = new X509Certificate(certIN);
        assertNotNull(stream);
        CRLEdit editor = new CRLEdit(stream);
        editor.addCertificate(hgpCert);
        editor.signCRL(keys.getSecond()[0], keys.getFirst());

    }

    @Test
    public void loadAllNewCerts() throws Exception {
        InputStream keyStore = CRLEditTest.class.getResourceAsStream("/certificates/application.jks");
        assertNotNull(keyStore);
        KeyStore store = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "JKS");
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getKeyEntry(store, ALIAS, "geheim".toCharArray());
        InputStream stream = CRLEditTest.class.getResourceAsStream("/crl/unichorn.crl");
        InputStream streamTrust = CRLEditTest.class.getResourceAsStream("/crl/privateTrust.xml");
        TrustStatusListType trustList = TrustListLoader.loadTrust(streamTrust);
        TrustListManager trustGetter = new TrustListManager(trustList);
        assertNotNull(stream);
        CRLEdit editor = new CRLEdit(stream);
        for (X509Certificate trustCert: trustGetter.getAllCerts()) {
            editor.addCertificate(trustCert);
        }
        editor.signCRL(keys.getSecond()[0], keys.getFirst());
        File temp = File.createTempFile("privCRL", ".crl");
        FileOutputStream out = new FileOutputStream(temp);
        editor.storeCRL(out);
    }
}
