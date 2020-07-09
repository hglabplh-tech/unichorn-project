package org.harry.security.util.keystores;

import iaik.utils.ExtendedProvider;

import java.security.Provider;

public class UnicProvider extends Provider {
    protected UnicProvider() {
        super("UnicProvider", 1.0d, "Provides a own KeyStore");
        this.put("KeyStore.UnicP12", "org.harry.security.util.keystores.UnichornPKCS12Store");
    }

    public static UnicProvider getInstance() {
        return new UnicProvider();
    }
}
