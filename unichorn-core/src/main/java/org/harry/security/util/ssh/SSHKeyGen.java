package org.harry.security.util.ssh;

import com.jcraft.jsch.*;

import java.io.IOException;

public class SSHKeyGen {

    public static void generateKeyPair(KeyPairType type, String passphrase, String fName) throws JSchException, IOException {
        JSch shell = new JSch();
        KeyPair pair;
        switch(type) {
            case RSA:
                pair = KeyPairRSA.genKeyPair(shell, KeyPair.RSA, 4096);
                break;
            case DSA:
                pair = KeyPairRSA.genKeyPair(shell, KeyPair.DSA, 1024);
                break;
            case ECDSA:
                pair = KeyPairRSA.genKeyPair(shell, KeyPair.ECDSA, 571);
                break;
            default:
                pair = KeyPairRSA.genKeyPair(shell, KeyPair.RSA, 1024);
        }
        pair.setPassphrase(passphrase);
        pair.writePrivateKey(fName);
        pair.writePublicKey(fName + ".pub", "Public Key for host");
        System.out.println("Finger print: "+ pair.getFingerPrint());
        pair.dispose();

    }

    public static enum KeyPairType {
        DSA,
        ECDSA,
        PKCS8,
        RSA;
    }
}
