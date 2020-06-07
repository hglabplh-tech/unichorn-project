package org.harry.security;

import java.io.File;

public class CommonConst {

    /**
     * The applications configuration and data directory
     */
    public static String APP_DIR;

    /**
     * The directory in which the private key store, the trust-lists and the crl resides
     */
    public static String APP_DIR_TRUST;

    /**
     * Here the PKCS11 dll's reside
     */
    public static String APP_DIR_DLL;

    /**
     * The working directory used by responder
     */
    public static String APP_DIR_WORKING;

    /**
     * The file-name of the application properties
     */
    public static final String PROP_APPLICATAION_PROPERTIES = "application.properties";

    /**
     * The file-name of the responder list of the responders which are used by
     * requested certificates to see which responders are used by the different PKI's.
     * This file resides in the applications configuration root directory
     */
    public static final String PROP_RESPONDER_LIST_FILE = "responders.used";


    /**
     * The file-name of the application properties
     */
    public static final String PROP_PASSWD_PROPERTIES = "passwd.properties";

    /**
     * Sub-Path for dll's
     */
    public static final String PROP_DLLPATH = "dll";

    /**
     * The base URL for the services
     */
    public static final String BASE_URL = "https://localhost/unichorn-responder-1.1-SNAPSHOT";

    /**
     * The sub-path to the timestamp-service
     */
    public static final String TSP_URL = BASE_URL + "/rest/tsp";

    /**
     * The sub-path to the ocsp-responder
     */
    public static final String OCSP_URL  = BASE_URL + "/rest/ocsp";

    /**
     * The sub-path to the signing-service
     */
    public static final String SIGNING_URL  = BASE_URL + "/rest/signing";

    /**
     * The sub-path to the admin-service
     */
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
        File dirDll = new File(userDir, PROP_DLLPATH);
        if (!dirDll.exists()) {
            dirDll.mkdirs();
        }
        File dirWorking = new File(userDir, "working");
        if (!dirWorking.exists()) {
            dirWorking.mkdirs();
        }
        APP_DIR_TRUST = dirTrust.getAbsolutePath();
        APP_DIR_DLL = dirDll.getAbsolutePath();
        APP_DIR_WORKING = dirWorking.getAbsolutePath();
        APP_DIR= userDir;
    }
}
