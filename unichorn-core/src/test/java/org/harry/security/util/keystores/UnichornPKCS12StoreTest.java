package org.harry.security.util.keystores;

import iaik.utils.Util;
import iaik.x509.X509Certificate;
import org.harry.security.testutils.TestBase;
import org.harry.security.util.algoritms.CryptoAlg;
import org.junit.Test;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Enumeration;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class UnichornPKCS12StoreTest extends TestBase {

    @Test
    public void loadStore() throws Exception {
        KeyStore store = KeyStore.getInstance("UnicP12");
        InputStream p12Input = UnichornPKCS12StoreTest
                .class.getResourceAsStream("/certificates/application.p12");
        store.load(p12Input, "geheim".toCharArray());
        readAndDisplay(store, false);
    }

    @Test
    public void copyStore() throws Exception {
        KeyStore store = KeyStore.getInstance("UnicP12");
        KeyStore target = KeyStore.getInstance("UnicP12");
        target.load(null, "geheim".toCharArray());
        InputStream p12Input = UnichornPKCS12StoreTest
                .class.getResourceAsStream("/certificates/application.p12");
        store.load(p12Input, "geheim".toCharArray());
        target.load(null, "geheim".toCharArray());
        readAndDisplay(store, true);
        copyToStore(store, target);
        File file = File.createTempFile("store", ".p12");
        UP12StoreParams params = new UP12StoreParams(new FileOutputStream(file)
                ,"geheim".toCharArray()
                ,CryptoAlg.PBE_SHAA_40BITSRC2_CBC.getAlgId()
                ,CryptoAlg.PBE_SHAA3_KEY_TRIPLE_DES_CBC.getAlgId());
        target.store(params);
        store = KeyStore.getInstance("UnicP12");
        store.load(new FileInputStream(file), "geheim".toCharArray());
        readAndDisplay(store, false);
    }

    @Test
    public void addCertificate() throws Exception {
        KeyStore store = KeyStore.getInstance("UnicP12");
        InputStream certInput = UnichornPKCS12StoreTest
                .class.getResourceAsStream("/certificates/hgp.cer");
        X509Certificate certToAdd = new X509Certificate(certInput);
        store.load(null, null);
        store.setCertificateEntry("acert", certToAdd);
        File file = File.createTempFile("storeAddedCert", ".p12");
        OutputStream stream = new FileOutputStream(file);
        UP12StoreParams params = new UP12StoreParams(stream, "geheim".toCharArray(),
                null, null);
        store.store(params);
        store = KeyStore.getInstance("UnicP12");
        store.load(new FileInputStream(file), "geheim".toCharArray());
        int i = store.size();
        readAndDisplay(store, false);
        Certificate compCert = store.getCertificate("acert");
        X509Certificate added = Util.convertCertificate(compCert);
        assertThat(added.getSerialNumber(), is(certToAdd.getSerialNumber()));
    }

    private void copyToStore(KeyStore store, KeyStore target) throws Exception {
        Enumeration<String> aliases = store.aliases();
        aliases = store.aliases();
        System.out.println("\n\n\n\n\n");
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (store.isKeyEntry(alias)) {
                PrivateKey key = (PrivateKey)store.getKey(alias, "geheim".toCharArray());
                Certificate[] chain = store.getCertificateChain(alias);
                target.setKeyEntry(alias, key, "geheim".toCharArray(), chain);
            }
        }
    }

    private void readAndDisplay(KeyStore store, boolean deleteFirst) throws Exception {
        Enumeration<String> aliases = store.aliases();
        aliases = store.aliases();
        System.out.println("\n\n\n\n\n");
        while(aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (store.isKeyEntry(alias)) {
                if (deleteFirst) {
                    store.deleteEntry(alias);
                    deleteFirst = false;
                } else {
                    PrivateKey key = (PrivateKey) store.getKey(alias, "geheim".toCharArray());
                    System.out.println("Key format: " + key.getFormat() + " Algorithm: " + key.getAlgorithm());
                    Certificate[] chain = store.getCertificateChain(alias);
                    System.out.println("============================================================= BEGIN ===============================\n\n\n\n");
                    for (Certificate cert : chain) {
                        System.out.println(Util.convertCertificate(cert).toString(true));
                    }
                    System.out.println("============================================================= END ===============================\n\n\n\n");
                }
            } else if (store.isCertificateEntry(alias)) {
                Certificate cert = store.getCertificate(alias);
                X509Certificate iaikCert = Util.convertCertificate(cert);
                System.out.println("============================================================= BEGIN ===============================\n\n\n\n");
                System.out.println(iaikCert.toString(true));
                System.out.println("============================================================= END ===============================\n\n\n\n");
            }
        }
    }



}
