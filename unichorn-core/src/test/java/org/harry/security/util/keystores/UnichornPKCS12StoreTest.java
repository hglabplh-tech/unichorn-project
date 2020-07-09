package org.harry.security.util.keystores;

import iaik.utils.Util;
import iaik.x509.X509Certificate;
import org.harry.security.testutils.TestBase;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Enumeration;

public class UnichornPKCS12StoreTest extends TestBase {

    @Test
    public void loadStore() throws Exception {
        KeyStore store = KeyStore.getInstance("UnicP12");
        InputStream p12Input = UnichornPKCS12StoreTest
                .class.getResourceAsStream("/certificates/application.p12");
        store.load(p12Input, "geheim".toCharArray());
        Enumeration<String> aliases = store.aliases();
        System.out.println("\n\n\n\n\n");
        while(aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            PrivateKey key = (PrivateKey)store.getKey(alias, "geheim".toCharArray());
            System.out.println("Key format: " + key.getFormat() + " Algorithm: " + key.getAlgorithm());
            Certificate[] chain = store.getCertificateChain(alias);
            System.out.println("============================================================= BEGIN ===============================\n\n\n\n");
            for (Certificate cert: chain) {
                System.out.println(Util.convertCertificate(cert).toString(true));
            }
            System.out.println("============================================================= END ===============================\n\n\n\n");
        }
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
        Enumeration<String> aliases = store.aliases();
        System.out.println("\n\n\n\n\n");
        while(aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            PrivateKey key = (PrivateKey)store.getKey(alias, "geheim".toCharArray());
            System.out.println("Key format: " + key.getFormat() + " Algorithm: " + key.getAlgorithm());
            Certificate[] chain = store.getCertificateChain(alias);
            System.out.println("============================================================= BEGIN ===============================\n\n\n\n");
            target.setKeyEntry(alias, key, "geheim".toCharArray(), chain);
            for (Certificate cert: chain) {
                System.out.println(Util.convertCertificate(cert).toString(true));
            }
            System.out.println("============================================================= END ===============================\n\n\n\n");
        }
        File file = File.createTempFile("store", ".p12");
        target.store(new FileOutputStream(file), "geheim".toCharArray());
        store = KeyStore.getInstance("UnicP12");
        store.load(new FileInputStream(file), "geheim".toCharArray());
        aliases = store.aliases();
        System.out.println("\n\n\n\n\n");
        while(aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            PrivateKey key = (PrivateKey)store.getKey(alias, "geheim".toCharArray());
            System.out.println("Key format: " + key.getFormat() + " Algorithm: " + key.getAlgorithm());
            Certificate[] chain = store.getCertificateChain(alias);
            System.out.println("============================================================= BEGIN ===============================\n\n\n\n");
            for (Certificate cert: chain) {
                System.out.println(Util.convertCertificate(cert).toString(true));
            }
            System.out.println("============================================================= END ===============================\n\n\n\n");
        }
    }


}
