package org.harry.security.util.certandkey;

import iaik.asn1.structures.AlgorithmID;
import iaik.security.provider.IAIK;
import iaik.utils.Util;
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
import java.util.Enumeration;

public class KeyStoreTool {

    public static String APP_DIR;

    public static final String KEYSTORE_FNAME = "application.p12";

    public static final String TRUSTSTORE_LOC = System.getProperty("java.home") + "/lib/security/cacerts";

    static {
        String userDir = System.getProperty("user.home");
        userDir = userDir + "\\AppData\\Local\\MySigningApp";
        File dir = new File(userDir);
        if (!dir.exists()){
            dir.mkdirs();
        }
        APP_DIR= userDir;
    }

    public static KeyStore initStore(String type, String password) {
        try {
            KeyStore store = KeyStore.getInstance(type, IAIK.getInstance());
            store.load(null, password.toCharArray());
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

    public static KeyStore loadTrustStore() {
        try {
            KeyStore store = KeyStore.getInstance("JKS");
            FileInputStream resource = new FileInputStream(new File(TRUSTSTORE_LOC));
            store.load(resource, "changeit".toCharArray());
            resource.close();
            Logger.trace("Trust store " + TRUSTSTORE_LOC + " is loaded");
            return store;
        } catch (Exception ex) {
            Logger.trace(ex);
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

            String foundID = null;
            boolean found = false;
            Tuple<PrivateKey, X509Certificate[]> result;
            Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements() && !found) {
                String alias = aliases.nextElement();
                if (alias.contains("User")  && !alias.contains("EC")) {
                    Logger.trace("Alias found is:" + alias);
                    found = true;
                    foundID = alias;
                }
            }
            if (found && store.containsAlias(foundID)) {
                Certificate[] certChain = store.getCertificateChain(foundID);
                X509Certificate [] iaiks = Util.convertCertificateChain(certChain);
                PrivateKey key = (PrivateKey)store.getKey(foundID, "geheim".toCharArray());
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
            Certificate[] certChain = null;
            certChain = store.getCertificateChain(alias);
            if (certChain != null) {
                X509Certificate[] iaiks = new X509Certificate[certChain.length];
                int index = 0;
                for (Certificate thisCert : certChain) {
                    X509Certificate iaik = new X509Certificate(thisCert.getEncoded());
                    iaiks[index] = iaik;
                    index++;
                }
                return iaiks;
            } else {
                return new X509Certificate[0];
            }

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

    public static void addCertificate(KeyStore store, Certificate certificate, String alias) {
        try {

            if (store.containsAlias(alias)) {
                // Warning
                store.setCertificateEntry(alias, certificate);
            } else {
                store.setCertificateEntry(alias, certificate);
            }

        } catch (Exception ex) {
            Logger.trace(" Error occurred: " + ex.getMessage());
            throw new IllegalStateException("add certificate entry failed", ex);
        }
    }

    public static void addCertificateChain(KeyStore store, X509Certificate[] certificateChain) {
        try {
            KeyStore appStore = KeyStoreTool.loadAppStore();
            Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(appStore);
            store.setKeyEntry(certificateChain[0].getSubjectDN().getName(),
                    keys.getFirst(),
                    "geheim".toCharArray(),
                    certificateChain);
        } catch (Exception ex) {
            throw new IllegalStateException("delete entry failed", ex);
        }
    }

    public static void addKey(KeyStore store, PrivateKey key, char [] passwd,
                              X509Certificate[] certChain, String alias) {
        try {


                // Warning
                store.setKeyEntry(alias, key, passwd,certChain);


        } catch (Exception ex) {
            throw new IllegalStateException("delete entry failed", ex);
        }
    }

    public static enum StoreType {
        PKCS12("pkcs12"),
        IAIKKeyStore("IAIKKeyStore"),
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
