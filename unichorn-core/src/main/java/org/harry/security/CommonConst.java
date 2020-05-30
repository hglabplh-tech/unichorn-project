package org.harry.security;

import java.io.File;

public class CommonConst {

    public static String APP_DIR;

    public static String APP_DIR_TRUST;

    public static String APP_DIR_DLL;

    public static final String PROP_FNAME = "application.properties";

    public static final String PROP_DLLPATH = "dll";

    public static final String PROP_TLS = "harry.trust.listurls";

    public static final String BASE_URL = "https://localhost/unichorn-responder-1.0-SNAPSHOT";

    public static final String TSP_URL = BASE_URL + "/rest/tsp";

    public static final String OCSP_URL  = BASE_URL + "/rest/ocsp";

    public static final String SIGNING_URL  = BASE_URL + "/rest/signing";

    public static final String ADMIN_URL  = BASE_URL + "/rest/admin";

    static {
        String userDir = System.getProperty("user.home");
        userDir = userDir + "\\AppData\\Local\\MySigningApp";
        File dir = new File(userDir);
        if (!dir.exists()){
            dir.mkdirs();
        }
        File dirTrust = new File(userDir, "trustedLists");
        if (!dirTrust.exists()) {
            dirTrust.mkdirs();
        }
        File dirDll = new File(userDir, "dll");
        if (!dirDll.exists()) {
            dirDll.mkdirs();
        }
        APP_DIR_TRUST = dirTrust.getAbsolutePath();
        APP_DIR_DLL = dirDll.getAbsolutePath();
        APP_DIR= userDir;
    }
}
