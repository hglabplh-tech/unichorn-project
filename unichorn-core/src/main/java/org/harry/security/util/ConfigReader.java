package org.harry.security.util;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.etsi.uri._02231.v2_.TrustStatusListType;
import org.harry.security.util.certandkey.CSRHandler;
import org.harry.security.util.httpclient.ClientFactory;
import org.harry.security.util.trustlist.TrustListLoader;
import org.harry.security.util.trustlist.TrustListManager;

import java.io.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Scanner;

import static org.harry.security.CommonConst.*;

public class ConfigReader {

    /**
     * The key store path
     */
    public static final String PROP_KEYSTORE_PATH = "harry.signer.keystore";

    /**
     * Path to a attribute-certificate
     */
    public static final String PROP_ATTR_CERT_PATH = "harry.signer.attributeCert";

    /**
     * The KeyStore Type
     */
    public static final String PROP_KEYSTORE_TYPE = "harry.signer.storeType";

    /**
     * The keystore password
     */
    public static final String PROP_KEYSTORE_PASS = "harry.signer.storePass";

    /**
     * The keystore alias
     */
    public static final String PROP_KEYSTORE_ALIAS = "harry.signer.storeAlias";

    /**
     * the encrypt / decrypt password
     */
    public  final static String PROP_DECR_PASSWORD = "harry.encrdecr.password";

    /**
     * algorithm for decryption / encryption
     */
    public final static String PROP_DECR_PEBALG = "harry.encrdecr.pbeAlg";

    /**
     * The algorithm for envelöoping data
     */
    public final static String PROP_DECR_ENVALG = "harry.encrdecr.envelopAlg";

    /**
     * The country attribute for a certificate
     */
    public static final String PROP_CERT_COUNTRY = "harry.cert.country";

    /**
     * The organization attribute for a certificate
     */
    public static final String PROP_CERT_ORG = "harry.cert.organization";

    /**
     * The organization unit attribute for a certificate
     */
    public static final String PROP_CERT_ORG_UNIT = "harry.cert.organizationalUnit";

    /**
     * The common name attribute for a certificate
     */
    public static final String PROP_CERT_COMMON_NAME = "harry.cert.cName";

    /**
     * The pin for pkcs11 card processing attribute for a certificate
     */
    public static final String PROP_PKCS11_PIN = "harry.pkcs11.pin";

    /**
     * Property for the trust-list URL's
     */
    public static final String PROP_TLS = "harry.trust.listurls";


    /**
     * A HttpClient for accept all input
     */
    static final HttpClient httpClient = ClientFactory.getAcceptAllHttpClient();


    /**
     * The protecting CTOr
     */
    private ConfigReader() {
    }

    /**
     * Initialize a new properties object
     * @return
     */
    public static Properties init() {
        File propFile = new File(APP_DIR, PROP_FNAME);
        Properties props = new Properties();
        if (!propFile.exists()) {

            props.setProperty(PROP_KEYSTORE_PATH, "./.keystore");
            props.setProperty(PROP_ATTR_CERT_PATH, "./attributeCert.cer");
            props.setProperty(PROP_KEYSTORE_TYPE, "PKCS12");

            props.setProperty(PROP_KEYSTORE_ALIAS, "invalid");
            props.setProperty(PROP_CERT_COUNTRY, "");
            props.setProperty(PROP_CERT_ORG, "");
            props.setProperty(PROP_CERT_ORG_UNIT, "");
            props.setProperty(PROP_CERT_COMMON_NAME, "");

            props.setProperty(PROP_DECR_PEBALG, "");
            props.setProperty(PROP_DECR_ENVALG, "");
            props.setProperty(PROP_TLS, "");
        } else {
            try {
                props.load(new FileInputStream(propFile));
            } catch (IOException e) {

            }
        }
        return  props;
    }


    /**
     * Save the application properties to a given file
     * @param properties
     */
    public static void saveProperties(Properties properties) {
        FileOutputStream propFile = null;
        try {
            File theFile= new File(APP_DIR, PROP_FNAME);
            propFile = new FileOutputStream(theFile);
            properties.store(propFile, "Configuration for Corona-Project");
            propFile.close();
            CSRHandler.setAppProperties(theFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * load the applications properties store
     * @return return the MainProperties object
     */
    public static MainProperties loadStore() {
        try {
            Properties props = new Properties();
            props.load(new FileInputStream(new File(APP_DIR, "application.properties")));
            String path = props.getProperty(PROP_KEYSTORE_PATH, "./.keystore");
            String attrCertPath = props.getProperty(PROP_ATTR_CERT_PATH, "./attributeCert.cer");
            String type = props.getProperty(PROP_KEYSTORE_TYPE, "PKCS12");
            String password = props.getProperty(PROP_KEYSTORE_PASS);
            String alias = props.getProperty(PROP_KEYSTORE_ALIAS, "invalid");
            String country = props.getProperty(PROP_CERT_COUNTRY, "");
            String organization = props.getProperty(PROP_CERT_ORG, "");
            String unit = props.getProperty(PROP_CERT_ORG_UNIT, "");
            String commonName = props.getProperty(PROP_CERT_COMMON_NAME, "");
            String decrPasswd = props.getProperty(PROP_DECR_PASSWORD);
            String pbeAlg = props.getProperty(PROP_DECR_PEBALG, "");
            String envelopAlg = props.getProperty(PROP_DECR_ENVALG, "");
            String trustLists = props.getProperty(PROP_TLS, "");
            String pin = props.getProperty(PROP_PKCS11_PIN, null);

            String [] array = trustLists.split(";");
            List<String> trusts = new ArrayList<>();
            for (String value:array) {
                trusts.add(value.trim());
            }
            return new MainProperties(path,
                    type,
                    password,
                    alias,
                    country,
                    organization,
                    unit,
                    commonName,
                    decrPasswd,
                    pbeAlg,
                    envelopAlg).setTrustLists(trusts)
                    .setAttrCertPath(attrCertPath)
                    .setPkcs11Pin(pin);

        } catch (IOException e) {
            throw new IllegalStateException("properties not loaded", e);
        }
    }

    /**
     * Load a specific trust list
     * @param trustName the trust-list name searched in the directory for trust-files
     * @return the list
     */
    public static TrustStatusListType loadSpecificTrust(String trustName) {
        File trustFile = new File(APP_DIR_TRUST, trustName +  ".xml").getAbsoluteFile();
        FileInputStream in;
        try {
            in = new FileInputStream(trustFile);
            return TrustListLoader.loadTrust(in);
        } catch(Exception ex) {
            throw new IllegalStateException("trust list load failed ", ex);
        }

    }

    /**
     * Load all trust - lists in the directory for trust-lists and give back the list of the TrustListManager objects
     * @return return the managers list
     */
    public static List<TrustListManager> loadAllTrusts()  {
        List<TrustListManager> theTrusts = new ArrayList<>();
        FileInputStream in;
        try {
            File trustFileDir = new File(APP_DIR_TRUST);
            for (File trustFile : trustFileDir.listFiles()) {
                if (trustFile.getName().contains(".xml")) {
                    in = new FileInputStream(trustFile);
                TrustStatusListType trustList = TrustListLoader.loadTrust(in);
                TrustListManager walker = new TrustListManager(trustList);
                theTrusts.add(walker);
                }
            }
            return theTrusts;
        } catch(Exception ex) {
            throw new IllegalStateException("trusts not loaded ", ex);

        }
    }

    /**
     * download several trust-list from a given url and store it in the trust - list- directory
     * @param urlList the List of URL Strings of the lists
     */
    public static void downloadTrusts(List<String> urlList) {
        try {
            for (String url : urlList) {
                downloadWriteOneTrust(url);
            }
        } catch (IOException ex) {
            throw new IllegalStateException("download trust list failed", ex);
        }
    }

    /**
     * really download the list
     * @param url the download url
     * @throws IOException error case
     */
    public static void downloadWriteOneTrust(String url) throws IOException {

        try {
            URL trustURL = new URL(url);
            System.out.println("Trust List URL: " + trustURL.toString());
            HttpGet httpGet = new HttpGet(trustURL.toURI());

            try {
            HttpResponse response = httpClient.execute(httpGet);
                StatusLine statusLine = response.getStatusLine();
                System.out.println(statusLine.getStatusCode() + " " + statusLine.getReasonPhrase());
                HttpEntity entity = response.getEntity();
                InputStream xmlIN = entity.getContent();
                byte [] buffer = new byte[4096];
                String rest = url.substring(url.lastIndexOf("/") + 1);
                FileOutputStream fileOut =
                         new FileOutputStream(new File(APP_DIR_TRUST, rest).getAbsoluteFile());
                int read = 0;
                while ((read = xmlIN.read(buffer)) > 0) {
                    fileOut.write(buffer, 0, read);
                }
                fileOut.close();
                xmlIN.close();
                httpGet.releaseConnection();
            } catch (Exception ex) {
                throw new IllegalStateException("http client error", ex);
            }
        } catch (Exception ex) {
            throw new IllegalStateException("trust-list download failed", ex);
        }
    }

    /**
     * read the password from console or line in
     * @param text the prompt- text
     * @return the passwd-string
     */
    private static String readPassWD(String text) {
        Console console = System.console();
        char[] passwordChars = null;
        if (console != null) {
            console.printf(text);
            passwordChars = console.readPassword();
        } else {
            System.out.println(text);
            try {
                Character [] ideInput;
                String result = readLineIDE();

                return result;
            } catch (IOException e) {
                throw new IllegalStateException("cannot read the thing this is strange", e);

            }
        }
        String passwordString = new String(passwordChars);
        return passwordString;

    }

    /**
     * read a line given in with the Scanner
     * @return the string
     * @throws IOException error case
     */
    private static String readLineIDE() throws IOException {
        String character;
        Scanner scanner = new Scanner(System.in);
        character = scanner.next();
        return character;
    }

    /**
     * Main Properties for the application properties this is the
     * real application configuration object
     */
    public static class MainProperties {
        private  String keystorePath;
        private  String attrCertPath;
        private  String keystoreType;
        private String keystorePass;
        private  String alias;

        private  String pbeAlg;
        private  String envelopAlg;
        private  String decryptPWD;

        private  String country;
        private  String organization;
        private  String  unit;
        private  String commonName;
        private  List<String> trustLists;
        private String pkcs11Pin;

        /**
         * CTOr for the Main Properties
         * @param keystorePath the path to the keystore
         * @param keystoreType the keystore type
         * @param keystorePass the keystore password
         * @param alias the keystore alias
         * @param country the country setting for a certificate
         * @param organization the organization setting for a certificate
         * @param unit the organization-unit setting for a certificate
         * @param commonName the common name setting for a certificate
         * @param decrPasswd the password for de-/ encryption
         * @param pbeAlg the crypto algorithm for decrypt / encrypt
         * @param envelopAlg the crypto algorithm for envelop
         */
        public MainProperties(String keystorePath, String keystoreType,
                              String keystorePass, String alias, String country,
                              String organization, String unit, String commonName,
                                String decrPasswd, String pbeAlg, String envelopAlg) {
            this.keystorePath = keystorePath;
            this.keystoreType = keystoreType;
            this.keystorePass = keystorePass;
            this.alias = alias;
            this.country = country;
            this.organization = organization;
            this.unit = unit;
            this.commonName = commonName;
            this.decryptPWD = decrPasswd;
            this.pbeAlg = pbeAlg;
            this.envelopAlg = envelopAlg;
        }

        /**
         * Default CTOr
         */
        public MainProperties() {

        }

        /**
         * get the algorithm for encryption
         * @return the algorithm
         */
        public String getPbeAlg() {
            return pbeAlg;
        }


        /**
         * get the decryption password
         * @return the password
         */
        public String getDecryptPWD() {
            if (decryptPWD == null) {
                decryptPWD = readPassWD("Enter decrypt password:");
            }
            return decryptPWD;
        }

        /**
         * get the trust lists urls
         * @return the list-string
         */
        public List<String> getTrustLists() {
            return trustLists;
        }

        /**
         * set the urls for the trust-lists used for loading them
         * @param trustLists the urls list-string
         * @return this object
         */
        public MainProperties setTrustLists(List<String> trustLists) {
            this.trustLists = trustLists;
            return this;
        }

        /**
         * get the path to the keystore
         * @return the path
         */
        public String getKeystorePath() {
            return keystorePath;
        }

        /**
         * get the given key-store type
         * @return the type as string
         */
        public String getKeystoreType() {
            return keystoreType;
        }

        /**
         * get the keystore password
         * @return the password
         */
        public String getKeystorePass() {
            if (keystorePass == null) {
                keystorePass = readPassWD("type keystore password:");
            }
            return keystorePass;
        }

        /**
         * get the keystore-alias
         * @return the alias
         */
        public String getAlias() {
            return alias;
        }

        /**
         * get the algorithm for envelop data
         * @return the algorithm
         */
        public String getEnvelopAlg() {
            return envelopAlg;
        }

        /**
         * get the country for setting in certificate
         * @return the country
         */
        public String getCountry() {
            return country;
        }

        /**
         * get the organization for setting in certificate
         * @return the organization
         */
        public String getOrganization() {
            return organization;
        }

        /**
         * get the organization-unit for setting in certificate
         * @return the organization-unit
         */
        public String getUnit() {
            return unit;
        }

        /**
         * get the common-name for setting in certificate
         * @return the common-name
         */
        public String getCommonName() {
            return commonName;
        }

        /**
         * set the keystore path
         * @param keystorePath the path
         * @return this object
         */
        public MainProperties setKeystorePath(String keystorePath) {
            this.keystorePath = keystorePath;
            return this;
        }

        /**
         * set the keystore-type
         * @param keystoreType the type
         * @return this object
         */
        public MainProperties setKeystoreType(String keystoreType) {
            this.keystoreType = keystoreType;
            return this;
        }

        /**
         * set the keystore password
         * @param keystorePass the password
         * @return this object
         */
        public MainProperties setKeystorePass(String keystorePass) {
            this.keystorePass = keystorePass;
            return this;
        }

        /**
         * set the keystore-alias
         * @param alias the alias
         * @return this object
         */
        public MainProperties setAlias(String alias) {
            this.alias = alias;
            return this;
        }

        /**
         * set the algorithm for de-/ encryption
         * @param pbeAlg the algorithm
         * @return this object
         */
        public MainProperties setPbeAlg(String pbeAlg) {
            this.pbeAlg = pbeAlg;
            return this;
        }

        /**
         * set the algorithm for envelop data
         * @param envelopAlg the algorithm
         * @return this object
         */
        public MainProperties setEnvelopAlg(String envelopAlg) {
            this.envelopAlg = envelopAlg;
            return this;
        }

        /**
         * set the password for decryption/ encryption
         * @param decryptPWD the password
         * @return this object
         */
        public MainProperties setDecryptPWD(String decryptPWD) {
            this.decryptPWD = decryptPWD;
            return this;
        }

        /**
         * set the country for use in a certificate
         * @param country the country
         * @return this object
         */
        public MainProperties setCountry(String country) {
            this.country = country;
            return this;
        }

        /**
         * set the organization for use in a certificate
         * @param organization the org
         * @return this object
         */
        public MainProperties setOrganization(String organization) {
            this.organization = organization;
            return this;
        }

        /**
         * set the organization unit for use in a certificate
         * @param unit the unit
         * @return this object
         */
        public MainProperties setUnit(String unit) {
            this.unit = unit;
            return this;
        }

        /**
         * set the common-name for use in a certificate
         * @param commonName the common-name
         * @return this object
         */
        public MainProperties setCommonName(String commonName) {
            this.commonName = commonName;
            return this;
        }

        /**
         * get the path of a attribute-certificate for use in signing
         * @return the path
         */
        public String getAttrCertPath() {
            return attrCertPath;
        }

        /**
         * set the path of a attribute-certificate for use in signing
         * @param attrCertPath the path
         * @return this object
         */
        public MainProperties setAttrCertPath(String attrCertPath) {
            this.attrCertPath = attrCertPath;
            return this;
        }

        /**
         * get the pin for a smart-card
         * @return the pin
         */
        public String getPkcs11Pin() {
            return pkcs11Pin;
        }

        /**
         * set the pin for a smart-card usage
         * @param pkcs11Pin the pin
         * @return this object
         */
        public MainProperties setPkcs11Pin(String pkcs11Pin) {
            this.pkcs11Pin = pkcs11Pin;
            return this;
        }
    }

}
