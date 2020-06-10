package harry.security.responder.resources;

import iaik.x509.X509Certificate;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.pmw.tinylog.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.*;

public class WorkerThread implements Runnable {
    private final File keyFile;
    private final KeyStore storeToApply;
    private final String passwd;
    private final String passwdUser;
    private final String storeType;

    public WorkerThread(File keyFile, KeyStore storeToApply, String passwd, String passwdUser ,String storeType) {
        this.keyFile = keyFile;
        this.storeToApply= storeToApply;
        this.passwd = passwd;
        this.storeType = storeType;
        this.passwdUser = passwdUser;
    }
    @Override
    public void run() {
        KeyStore privStore;
        try {
            if (!keyFile.exists()) {
                privStore = KeyStoreTool.initStore(storeType, passwd);
            } else {
                privStore = KeyStoreTool.loadStore(new FileInputStream(keyFile), passwd.toCharArray(), storeType);
            }
            Map<String, Tuple<PrivateKey, X509Certificate[]>> entryList = new HashMap<>();
            Enumeration<String> aliases = storeToApply.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                try {
                    Tuple<PrivateKey, X509Certificate[]> tuple = KeyStoreTool.
                            getKeyEntry(storeToApply, alias, passwdUser.toCharArray());
                    Logger.trace("collect key with alias :" + alias);
                    KeyStoreTool.addKey(privStore, tuple.getFirst(),
                            passwd.toCharArray(), tuple.getSecond(), alias);
                } catch (Exception ex) {
                    X509Certificate cert = KeyStoreTool.getCertificateEntry(storeToApply, alias);
                    if (cert != null) {
                        Logger.trace("collect certificate with subject DN: "+ cert.getSubjectDN().getName());
                        KeyStoreTool.addCertificate(privStore, cert, alias);
                    }
                }
                Logger.trace("add key with alias :" + alias);
            }
            Logger.trace("Before storing.... :" + keyFile.getAbsolutePath());
            KeyStoreTool.storeKeyStore(privStore, new FileOutputStream(keyFile), passwd.toCharArray());
            Logger.trace("Success storing.... :" + keyFile.getAbsolutePath());
        } catch (Exception ex){
            Logger.trace("error case keystore :  " + ex.getMessage());
            throw new IllegalStateException("apply keystore failed ", ex);
        }


    }
}
