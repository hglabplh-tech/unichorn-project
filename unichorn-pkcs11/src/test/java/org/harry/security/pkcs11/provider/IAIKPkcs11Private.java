package org.harry.security.pkcs11.provider;

import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11Exception;
import iaik.pkcs.pkcs11.provider.TokenManager;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Properties;

public class IAIKPkcs11Private extends IAIKPkcs11 {
    private static  TokenManager manager;
    public IAIKPkcs11Private() {

    }
    public IAIKPkcs11Private(Properties var1) {

    }
    public IAIKPkcs11Private(TokenManager manager) {

    }
    public static void setUp(TokenManager manager) {
        IAIKPkcs11Private.manager = manager;
    }

    public void initialize() {
        if (this.i != null) {
            this.i.clearSessionPool(false);
        }
        this.i = manager;
        this.m = new Hashtable();
        this.b();
        this.c();
        this.d();
    }

    protected  void d() {
        String var1;
        try {
            var1 = this.i.getModule().getInfo().getLibraryDescription();
        } catch (TokenException var5) {
            var1 = this.i.getModulePath();
        }

        String var2;
        try {
            var2 = this.i.getSlot().getSlotInfo().getSlotDescription();
        } catch (TokenException var4) {
            var2 = Long.toString(this.i.getSlot().getSlotID());
        }

        StringBuffer var3 = new StringBuffer("IAIK JCE Provider for PKCS#11 operating with ".length() + var1.length() + var2.length() + 20);
        var3.append("IAIK JCE Provider for PKCS#11 operating with ");
        var3.append("slot \"");
        var3.append(var2.trim());
        var3.append("\" of module \"");
        var3.append(var1.trim());
        var3.append('"');
        var3.append(" from PKCS#11 library \"");
        var3.append(this.i.getModulePath());
        var3.append('"');
        this.l = var3.toString();
    }

}


