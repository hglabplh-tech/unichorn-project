package org.harry.security.util;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class PrivateKeyStore {
    private String keyStorePath = "./privStore";
    private InputStream inStream = null;
    private OutputStream outStream = null;
    private KeyStore store = null;
    private ConfigReader.MainProperties properties = null;

    public PrivateKeyStore(ConfigReader.MainProperties properties, boolean keyStoreExists) throws Exception {
        File file = new File(keyStorePath).getAbsoluteFile();
        //inStream = new FileInputStream(file);
        if (keyStoreExists) {
            inStream = new FileInputStream(file);
            store = KeyStore.getInstance(properties.getKeystoreType());
            store.load(inStream, properties.getKeystorePass().toCharArray());
        } else {
            outStream = new FileOutputStream(file);
            store = KeyStore.getInstance(properties.getKeystoreType());
            store.load(null, null);
        }

        this.properties = properties;
    }

    public void addToStore(X509Certificate cert, PrivateKey privKey, String alias) throws  Exception {
        Certificate[] certChain = new Certificate[1];
        certChain[0] = cert;
        store.setKeyEntry(alias, privKey, properties.getKeystorePass().toCharArray(), certChain);

    }

    public void writeToStore() throws  Exception {
        store.store(outStream, properties.getKeystorePass().toCharArray());
        outStream.close();
    }

    public PrivateKey getPrivateKey(String alias) throws Exception {
        if (store.containsAlias(alias)) {
            return (PrivateKey) store.getKey(alias, properties.getKeystorePass().toCharArray());
        } else {
            return null;
        }
    }

}
