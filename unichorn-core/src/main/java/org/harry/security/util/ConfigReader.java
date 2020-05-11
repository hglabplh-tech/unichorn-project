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

public class ConfigReader {
    public static final String PROP_KEYSTORE_PATH = "harry.signer.keystore";

    public static final String PROP_KEYSTORE_TYPE = "harry.signer.storeType";

    public static final String PROP_KEYSTORE_PASS = "harry.signer.storePass";

    public static final String PROP_KEYSTORE_ALIAS = "harry.signer.storeAlias";

    public  final static String PROP_DECR_PASSWORD = "harry.encrdecr.password";
    public final static String PROP_DECR_PEBALG = "harry.encrdecr.pbeAlg";

    public final static String PROP_DECR_ENVALG = "harry.encrdecr.envelopAlg";

    public static final String PROP_CERT_COUNTRY = "harry.cert.country";

    public static final String PROP_CERT_ORG = "harry.cert.organization";

    public static final String PROP_CERT_ORG_UNIT = "harry.cert.organizationalUnit";

    public static final String PROP_CERT_COMMON_NAME = "harry.cert.cName";

    public static String APP_DIR;

    public static String APP_DIR_TRUST;

    public static final String PROP_FNAME = "application.properties";

    public static final String PROP_TLS = "harry.trust.listurls";

    static final HttpClient httpClient = ClientFactory.getAcceptAllHttpClient();

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
        APP_DIR_TRUST = dirTrust.getAbsolutePath();
        APP_DIR= userDir;
    }


    private ConfigReader() {
    }

    public static Properties init() {
        File propFile = new File(APP_DIR, PROP_FNAME);
        Properties props = new Properties();
        if (!propFile.exists()) {

            props.setProperty(PROP_KEYSTORE_PATH, "./.keystore");
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

    public static MainProperties loadStore() {
        try {
            Properties props = new Properties();
            props.load(new FileInputStream(new File(APP_DIR, "application.properties")));
            String path = props.getProperty(PROP_KEYSTORE_PATH, "./.keystore");
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
                    envelopAlg).setTrustLists(trusts);
        } catch (IOException e) {
            throw new IllegalStateException("properties not loaded", e);
        }
    }

    public static TrustStatusListType loadSpecificTrust(String trustName) {
        File trustFile = new File(APP_DIR_TRUST, trustName +  ".xml").getAbsoluteFile();
        FileInputStream in;
        try {
            in = new FileInputStream(trustFile);
            return TrustListLoader.loadTrust(in);
        } catch(IOException ex) {
            throw new IllegalStateException("trust list load failed ", ex);
        }

    }

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

    public static void downloadTrusts(List<String> urlList) {
        try {
            for (String url : urlList) {
                downloadWriteOneTrust(url);
            }
        } catch (IOException ex) {
            throw new IllegalStateException("download trust list failed", ex);
        }
    }

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

    private static String readLineIDE() throws IOException {
        String character;
        Scanner scanner = new Scanner(System.in);
        character = scanner.next();
        return character;
    }

    public static class MainProperties {
        private  String keystorePath;
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

        public MainProperties() {

        }

        public String getPbeAlg() {
            return pbeAlg;
        }



        public String getDecryptPWD() {
            if (decryptPWD == null) {
                decryptPWD = readPassWD("Enter decrypt password:");
            }
            return decryptPWD;
        }

        public List<String> getTrustLists() {
            return trustLists;
        }

        public MainProperties setTrustLists(List<String> trustLists) {
            this.trustLists = trustLists;
            return this;
        }

        public String getKeystorePath() {
            return keystorePath;
        }

        public String getKeystoreType() {
            return keystoreType;
        }

        public String getKeystorePass() {
            if (keystorePass == null) {
                keystorePass = readPassWD("type keystore password:");
            }
            return keystorePass;
        }

        public String getAlias() {
            return alias;
        }

        public String getEnvelopAlg() {
            return envelopAlg;
        }

        public String getCountry() {
            return country;
        }

        public String getOrganization() {
            return organization;
        }

        public String getUnit() {
            return unit;
        }

        public String getCommonName() {
            return commonName;
        }

        public MainProperties setKeystorePath(String keystorePath) {
            this.keystorePath = keystorePath;
            return this;
        }

        public MainProperties setKeystoreType(String keystoreType) {
            this.keystoreType = keystoreType;
            return this;
        }

        public MainProperties setKeystorePass(String keystorePass) {
            this.keystorePass = keystorePass;
            return this;
        }

        public MainProperties setAlias(String alias) {
            this.alias = alias;
            return this;
        }

        public MainProperties setPbeAlg(String pbeAlg) {
            this.pbeAlg = pbeAlg;
            return this;
        }

        public MainProperties setEnvelopAlg(String envelopAlg) {
            this.envelopAlg = envelopAlg;
            return this;
        }

        public MainProperties setDecryptPWD(String decryptPWD) {
            this.decryptPWD = decryptPWD;
            return this;
        }

        public MainProperties setCountry(String country) {
            this.country = country;
            return this;
        }

        public MainProperties setOrganization(String organization) {
            this.organization = organization;
            return this;
        }

        public MainProperties setUnit(String unit) {
            this.unit = unit;
            return this;
        }

        public MainProperties setCommonName(String commonName) {
            this.commonName = commonName;
            return this;
        }
    }

}
