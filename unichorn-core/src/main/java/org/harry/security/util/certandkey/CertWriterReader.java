package org.harry.security.util.certandkey;

import com.google.common.io.LineReader;
import iaik.utils.PemOutputStream;
import iaik.x509.X509Certificate;
import org.harry.security.util.SigningUtil;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Base64;

public class CertWriterReader {

    private X509Certificate certificate;

    private final static String HEADER = "-----BEGIN CERTIFICATE-----";

    private final static String FOOTER = "-----END CERTIFICATE-----";

    public static String APP_DIR;

    public static final String KEYSTORE_FNAME = "appKeyStore.jks";

    static {
        String userDir = System.getProperty("user.home");
        userDir = userDir + "\\AppData\\Local\\MySigningApp";
        File dir = new File(userDir);
        if (!dir.exists()){
            dir.mkdirs();
        }
        APP_DIR= userDir;
    }

    public CertWriterReader(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public CertWriterReader() {

    }

    public void writeToFilePEM(OutputStream stream) throws CertificateEncodingException, IOException {
        byte [] outArray = Base64.getEncoder().encode(certificate.getEncoded());
        PemOutputStream out = new PemOutputStream(stream, HEADER, FOOTER);
        certificate.writeTo(out);
        out.flush();
        out.close();
    }

    public void writeX509(OutputStream stream) throws IOException {
        this.certificate.writeTo(stream);
        stream.close();
    }

    public X509Certificate readX509(InputStream stream) throws IOException, CertificateException {
        X509Certificate cert = new X509Certificate(stream);
        return cert;
    }

    public X509Certificate readFromFilePEM(InputStream stream) throws CertificateException, IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Readable readable = new InputStreamReader(stream);
        LineReader in = new LineReader(readable);
        String line = in.readLine();
        byte [] buffer = new byte[64];
        if (line.equals(HEADER)) {
            String row = in.readLine();
            while (row != null && !row.isEmpty()) {
                if (!row.equals(FOOTER)) {
                    buffer = row.getBytes();
                    out.write(buffer, 0, row.length());
                }
                row = in.readLine();
            }
        }
        byte [] converted = Base64.getDecoder().decode(out.toByteArray());
        X509Certificate result = new X509Certificate(converted);
        return result;
    }

    public static KeyStoreBean loadSecrets(InputStream storeIN, String type, String keyPass, String alias) {
        KeyStoreBean bean;
        try {
            if (storeIN == null) {
                File keyStoreFile = new File(APP_DIR, KEYSTORE_FNAME);
                type = "JKS";
                storeIN = new FileInputStream(keyStoreFile);
            }
            KeyStore store = KeyStore.getInstance(type);

                store.load(storeIN, keyPass.toCharArray());

            if (store.containsAlias(alias)) {
                Certificate cert = store.getCertificate(alias);
                PrivateKey key = (PrivateKey) store.getKey(alias, keyPass.toCharArray());
                if (cert != null && key != null) {
                    bean = new KeyStoreBean(new X509Certificate(cert.getEncoded()), key);
                    return bean;
                } else {
                    bean = new KeyStoreBean(null, null);
                    return bean;
                }
            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e) {
            throw new IllegalStateException("error case", e);
        }
        finally {
            if (storeIN != null) {
                try {
                    storeIN.close();
                } catch(IOException e) {

                }
            }
        }
        return null;
    }
    public static class KeyStoreBean {
        private final X509Certificate selectedCert;
        private final PrivateKey selectedKey;

        public KeyStoreBean(X509Certificate selectedCert, PrivateKey selectedKey) {
            this.selectedCert = selectedCert;
            this.selectedKey = selectedKey;
        }

        public X509Certificate getSelectedCert() {
            return selectedCert;
        }

        public PrivateKey getSelectedKey() {
            return selectedKey;
        }
    }




    public static enum CertType {
        PEM,
        X509,
        P12;
    }

}