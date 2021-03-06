package org.harry.security.testutils;

import iaik.cms.SecurityProvider;
import iaik.cms.ecc.ECCelerateProvider;
import iaik.security.ec.provider.ECCelerate;
import iaik.security.provider.IAIKMD;
import org.harry.security.util.keystores.UnicProvider;
import org.junit.BeforeClass;
import org.pmw.tinylog.Configurator;
import org.pmw.tinylog.Level;
import org.pmw.tinylog.writers.ConsoleWriter;
import org.pmw.tinylog.writers.FileWriter;

import java.security.Security;
import java.util.Locale;

public class TestBase {

    @BeforeClass
    public static void init() {
        Configurator.defaultConfig()
                .writer(new ConsoleWriter())
                .locale(Locale.GERMANY)
                .level(Level.TRACE)
                .activate();
        IAIKMD.addAsProvider();
        ECCelerate ecProvider = ECCelerate.getInstance();
        Security.insertProviderAt(ecProvider, 3);
        Security.insertProviderAt(UnicProvider.getInstance(), 4);
        SecurityProvider.setSecurityProvider(new ECCelerateProvider());
    }
}
