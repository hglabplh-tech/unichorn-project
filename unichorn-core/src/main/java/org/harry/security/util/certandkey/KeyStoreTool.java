package org.harry.security.util.certandkey;

import iaik.x509.X509Certificate;
import org.harry.security.util.Tuple;


import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

public class KeyStoreTool {

   public static KeyStore loadStore(InputStream resource, char[] passwd, String type) {
       try {
           KeyStore store = KeyStore.getInstance(type);
           store.load(resource, passwd);
           resource.close();
           return store;
       } catch (Exception ex) {
           throw new IllegalStateException("cannot load keystore", ex);
       }
   }

    public static KeyStore initStore(String type) {
        try {
            KeyStore store = KeyStore.getInstance(type);
            store.load(null, null);
            return store;
        } catch (Exception ex) {
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
               PrivateKey key = (PrivateKey)store.getKey(alias, passwd);
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
            if (store.containsAlias(alias)) {
                Certificate cert = store.getCertificate(alias);
                result = new iaik.x509.X509Certificate(cert.getEncoded());
                return result;
            } else {
                throw new IllegalStateException("get entry failed");
            }
        } catch (Exception ex) {
            throw new IllegalStateException("get entry failed", ex);
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
            if (store.containsAlias(alias)) {
                // Warning
                store.setKeyEntry(alias, key, passwd, certChain);
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
