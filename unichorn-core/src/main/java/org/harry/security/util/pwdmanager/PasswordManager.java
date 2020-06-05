package org.harry.security.util.pwdmanager;

import iaik.utils.Util;
import org.apache.commons.io.IOUtils;
import org.harry.security.util.SigningUtil;
import org.harry.security.util.Tuple;

import javax.activation.DataSource;
import java.io.*;
import java.security.SecureRandom;
import java.util.*;

import static org.harry.security.CommonConst.APP_DIR;
import static org.harry.security.CommonConst.PROP_PASSWD_PROPERTIES;

public class PasswordManager {

    private final String masterPW;

    private final File pwdFile;

    public PasswordManager(String masterPW) {
        this.masterPW = masterPW;
        this.pwdFile = new File(APP_DIR, PROP_PASSWD_PROPERTIES);
    }

    public PasswordManager(String masterPW, File anyPWDFile) {
        this.masterPW = masterPW;
        this.pwdFile = anyPWDFile;
    }

    public void storePassword(String key, String username, String passwd) {
        Properties properties = new Properties();
        String toEncrypt = String.format("%s:%s", username, passwd);
        try {
            if (pwdFile.exists()) {
                properties.loadFromXML(new FileInputStream(pwdFile));
            }
            SigningUtil util = new SigningUtil();
            String base64Encr = util.encryptBase64CMS(toEncrypt, this.masterPW);
            String base64Key = Util.toBase64String(key.getBytes());
            properties.setProperty(base64Key, base64Encr);
            OutputStream stream = new FileOutputStream(pwdFile);
            properties.storeToXML(stream, "master pw store");
            stream.close();
        } catch (Exception ex) {
            throw new IllegalStateException("cannot store pw", ex);
        }
    }

        public Tuple<String, String> readPassword(String key) {
            Properties properties = new Properties();
            try {
                if (pwdFile.exists()) {
                    properties.loadFromXML(new FileInputStream(pwdFile));
                    String base64Key = Util.toBase64String(key.getBytes());
                    String value = properties.getProperty(base64Key);
                    if (value != null) {
                        return decryptEntry(value);
                    }
                } else {
                    throw new IllegalStateException("no file available");
                }
            } catch (Exception ex) {
                ex.printStackTrace();
                throw new IllegalStateException("cannot store pw", ex);
            }
            return null;

        }

    public String generatePass() {

        int leftLimit = 65;
        int rightLimit = 127;
        int targetStringLength = 26;
        SecureRandom random = new SecureRandom();
        random.setSeed(8787689698790790987L);
        StringBuilder buffer = new StringBuilder(targetStringLength);
        for (int i = 0; i < targetStringLength; i++) {
            int randomLimitedInt = leftLimit + (int)
                    (random.nextFloat() * (rightLimit - leftLimit + 1));
            buffer.append((char) randomLimitedInt);
        }
        String generatedString = buffer.toString();

        System.out.println(generatedString);
        return generatedString;
    }



        public Map<String, Tuple<String, String>> decryptStore() {
            Map<String, Tuple<String, String>> result = new HashMap<>();

            Properties properties = new Properties();
            try {
                if (pwdFile.exists()) {
                    properties.loadFromXML(new FileInputStream(pwdFile));
                    Set<String> names = properties.stringPropertyNames();
                    for (String name: names) {
                        String value = properties.getProperty(name);
                        Tuple<String, String> entry = decryptEntry(value);
                        byte[] decoded = Util.fromBase64String(name);
                        String key = new String(decoded);
                        result.put(key, entry);
                    }
                }
                return result;
            } catch (Exception ex) {
                throw new IllegalStateException("cannot decrypt store: " + ex.getMessage(), ex);
            }
        }

    private Tuple<String, String> decryptEntry(String toDecrypt) {
        SigningUtil util = new SigningUtil();
        String decoded = util.decryptBase64CMS(toDecrypt, this.masterPW);
        String username = decoded.substring(0, (decoded.lastIndexOf(':')));
        String passwd = decoded.substring((decoded.lastIndexOf(':') + 1));
        return new Tuple<>(username, passwd);
    }

    public static DataSource encryptStrong(String passwd, String masterPW) {
        SigningUtil util = new SigningUtil();
        DataSource ds = util.encryptStrongBase64CMS(passwd, masterPW);
        return ds;
    }

    public static String decryptStrong(DataSource input, String passwd, String masterPW) throws Exception {
        SigningUtil util = new SigningUtil();
        String result = util.decryptStrongBase64CMS(input.getInputStream(), passwd, masterPW);
        return result;
    }


}



