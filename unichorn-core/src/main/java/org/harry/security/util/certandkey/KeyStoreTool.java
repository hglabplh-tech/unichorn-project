package org.harry.security.util.certandkey;

import iaik.asn1.structures.AlgorithmID;
import iaik.security.provider.IAIK;
import iaik.x509.X509Certificate;
import org.harry.security.CMSSigner;
import org.harry.security.util.Tuple;
import org.pmw.tinylog.Logger;


import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;

public class KeyStoreTool {

    public static String APP_DIR;

    public static final String KEYSTORE_FNAME = "application.p12";

    public static final String ALIAS = "b998b1f7-04fe-42c6-8284-9fb21e604b60UserRSA";


    static {
        String userDir = System.getProperty("user.home");
        userDir = userDir + "\\AppData\\Local\\MySigningApp";
        File dir = new File(userDir);
        if (!dir.exists()){
            dir.mkdirs();
        }
        APP_DIR= userDir;
    }

    public static void removeProviders() {
        Security.removeProvider("IAIK");
        Security.removeProvider("IAIKMD");
    }
    public static KeyStore initStore(String type, String password) {
        try {
            KeyStore store = KeyStore.getInstance(type, IAIK.getInstance());
            store.load(null, null);
            return store;
        } catch (Exception ex) {
            throw new IllegalStateException("cannot load keystore", ex);
        }
    }

    public static KeyStore loadAppStore() {
        try {
            KeyStore store = KeyStore.getInstance("PKCS12", IAIK.getInstance());
            FileInputStream resource = new FileInputStream(new File(APP_DIR, KEYSTORE_FNAME));
            store.load(resource, "geheim".toCharArray());
            resource.close();

            return store;
        } catch (Exception ex) {
            throw new IllegalStateException("cannot load keystore", ex);
        }
    }

    public static KeyStore loadStore(InputStream resource, char[] passwd, String type) {
        try {
            KeyStore store = KeyStore.getInstance(type, IAIK.getInstance());
            store.load(resource, passwd);


            return store;
        } catch (Exception ex) {
            Logger.trace("exception thrown: type:" + ex.getClass().getCanonicalName() + " :: " + ex.getMessage());
            Logger.trace(ex);
            throw new IllegalStateException("cannot load keystore", ex);
        }
    }

    public static void storeKeyStore(KeyStore store, OutputStream target, char[] passwd) {
       try {

           store.store(target, passwd);
           target.close();

       } catch (Exception ex) {
           throw new IllegalStateException("store keystore failed", ex);
       }
    }

    public static Tuple<PrivateKey, X509Certificate[]> getKeyEntry(KeyStore store, String alias, char[] passwd) {
       try {

           Tuple<PrivateKey, X509Certificate[]> result;
           if (store.containsAlias(alias)) {
               Certificate[] certChain = store.getCertificateChain(alias);
               X509Certificate [] iaiks = new X509Certificate[certChain.length];
               int index = 0;
               for (Certificate thisCert: certChain) {
                   X509Certificate iaik = new X509Certificate(thisCert.getEncoded());
                   iaiks[index] = iaik;
                   index++;
               }

               PrivateKey key = (PrivateKey) store.getKey(alias, passwd);
               result = new Tuple<PrivateKey, X509Certificate[]>(key, iaiks);
           } else {
               throw new IllegalStateException("get entry failed");
           }

           return result;
       } catch (Exception ex) {
           String message = "get entry failed: cause: ";
           if (ex.getMessage() != null && ex.getCause() != null){
               message = message + ex.getMessage() + "||" + ex.getCause().getMessage();
           } else {
               message = ex.getMessage();
           }
           throw new IllegalStateException(message, ex);
       }

    }

    public static Tuple<PrivateKey, X509Certificate[]> getAppKeyEntry(KeyStore store) {
        try {

            Tuple<PrivateKey, X509Certificate[]> result;
            if (store.containsAlias(ALIAS)) {
                Certificate[] certChain = store.getCertificateChain(ALIAS);
                X509Certificate [] iaiks = new X509Certificate[certChain.length];
                int index = 0;
                for (Certificate thisCert: certChain) {
                    X509Certificate iaik = new X509Certificate(thisCert.getEncoded());
                    iaiks[index] = iaik;
                    index++;
                }
                PrivateKey key = (PrivateKey)store.getKey(ALIAS, "geheim".toCharArray());
                result = new Tuple<PrivateKey, X509Certificate[]>(key, iaiks);
            } else {
                throw new IllegalStateException("get entry failed");
            }

            return result;
        } catch (Exception ex) {
            String message = "get entry failed: cause: ";
            if (ex.getMessage() != null && ex.getCause() != null){
                message = message + ex.getMessage() + "||" + ex.getCause().getMessage();
            } else {
                message = ex.getMessage();
            }
            throw new IllegalStateException(message, ex);
        }

    }

    public static X509Certificate getCertificateEntry(KeyStore store, String alias) {
        try {

            X509Certificate result;

            Certificate cert = store.getCertificate(alias);
            result = new iaik.x509.X509Certificate(cert.getEncoded());

            return result;
        } catch (Exception ex) {
            throw new IllegalStateException("get entry failed", ex);
        }
    }

    public static X509Certificate[] getCertChainEntry(KeyStore store, String alias) {
        try {

            Certificate[] certChain = store.getCertificateChain(alias);
            X509Certificate [] iaiks = new X509Certificate[certChain.length];
            int index = 0;
            for (Certificate thisCert: certChain) {
                X509Certificate iaik = new X509Certificate(thisCert.getEncoded());
                iaiks[index] = iaik;
                index++;
            }

            return iaiks;

        } catch (Exception ex) {
            Logger.trace("Exception type is : " + ex.getClass().getCanonicalName());
            Logger.trace("Exception message is: " + ex.getMessage());
            throw new IllegalStateException("get entry failed " +ex.getMessage(), ex);
        }
    }

    public static void deleteEntry(KeyStore store, String alias) {
       try {

           if (store.containsAlias(alias)) {
               store.deleteEntry(alias);
           }

       } catch (Exception ex) {
           throw new IllegalStateException("delete entry failed", ex);
       }
    }

    public static void addCertificate(KeyStore store, X509Certificate certificate, String alias) {
        try {

            if (store.containsAlias(alias)) {
                // Warning
                store.setCertificateEntry(alias, certificate);
            } else {
                store.setCertificateEntry(alias, certificate);
            }

        } catch (Exception ex) {
            throw new IllegalStateException("delete entry failed", ex);
        }
    }

    public static void addKey(KeyStore store, PrivateKey key, char [] passwd,
                              X509Certificate[] certChain, String alias) {
        try {

           // KeyStore.Entry entry = new KeyStore.PrivateKeyEntry(key, certChain);
            if (store.containsAlias(alias)) {
                // Warning
                store.setKeyEntry(alias, key, passwd,certChain);
            } else {
                store.setKeyEntry(alias, key, passwd, certChain);
            }

        } catch (Exception ex) {
            throw new IllegalStateException("delete entry failed", ex);
        }
    }

    public static enum StoreType {
       PKCS12("pkcs12"),
        JKS("JKS");

       private String type;

        StoreType(String type) {
           this.type = type;
        }

        public String getType() {
            return type;
        }

    }
}
