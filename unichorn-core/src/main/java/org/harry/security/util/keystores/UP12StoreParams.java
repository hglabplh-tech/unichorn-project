package org.harry.security.util.keystores;

import iaik.asn1.structures.AlgorithmID;
import org.harry.security.util.algoritms.CryptoAlg;

import java.io.OutputStream;
import java.security.KeyStore;

public class UP12StoreParams implements KeyStore.LoadStoreParameter {
    private final OutputStream out;
    private final KeyStore.ProtectionParameter protectionParameter;

    private AlgorithmID authSafesAlg = CryptoAlg.PBE_SHAA_40BITSRC2_CBC.getAlgId();

    private AlgorithmID shroudedKeyBagAlg = CryptoAlg.PBE_SHAA_40BITSRC2_CBC.getAlgId();

    public UP12StoreParams(OutputStream outputStram, char[] password,
                           AlgorithmID authSafesAlg, AlgorithmID shroudedKeyBagAlg) {
        this(outputStram, (KeyStore.ProtectionParameter)(new KeyStore.PasswordProtection(password)),
                        authSafesAlg, shroudedKeyBagAlg);
    }

    public UP12StoreParams(OutputStream outputStream, KeyStore.ProtectionParameter protParam,
                AlgorithmID authSafesAlg, AlgorithmID shroudedKeyBagAlg) {
        this.out = outputStream;
        this.protectionParameter = protParam;
        if (authSafesAlg != null) {
            this.authSafesAlg = authSafesAlg;
        }
        if (shroudedKeyBagAlg != null) {
            this.shroudedKeyBagAlg = shroudedKeyBagAlg;
        }
    }

    public OutputStream getOutputStream() {
        return this.out;
    }

    public KeyStore.ProtectionParameter getProtectionParameter() {
        return this.protectionParameter;
    }

    public AlgorithmID getAuthSafesAlg() {
        return authSafesAlg;
    }

    public AlgorithmID getShroudedKeyBagAlg() {
        return shroudedKeyBagAlg;
    }
}


