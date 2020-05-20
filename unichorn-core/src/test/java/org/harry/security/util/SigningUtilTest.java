package org.harry.security.util;

import iaik.x509.X509Certificate;
import org.apache.commons.io.IOUtils;
import org.harry.security.testutils.TestBase;
import org.harry.security.util.algoritms.CryptoAlg;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.junit.Test;


import javax.activation.DataSource;
import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;

public class SigningUtilTest extends TestBase {

    @Test
    public void encryptDecryptCMS() throws Exception {
        InputStream input = SigningUtilTest.class.getResourceAsStream("/data/ergo.pdf");
        File output = File.createTempFile("encrcms", ".encr");
        File output2 = File.createTempFile("encrcms", ".decr");
        for (CryptoAlg cryptoAlg: CryptoAlg.values()) {
            if (cryptoAlg.getName().contains("PBE")) {
                SigningUtil util = new SigningUtil();
                SigningBean signingBean = new SigningBean()
                        .setCryptoAlgorithm(cryptoAlg)
                        .setDecryptPWD("changeit")
                        .setDataIN(input)
                        .setOutputPath(output.getAbsolutePath());
                DataSource source = util.encryptCMS(signingBean);
                util.writeToFile(source, signingBean);
                File inFile = new File(signingBean.getOutputPath());
                FileInputStream inStream = new FileInputStream(inFile);
                signingBean = new SigningBean()
                        .setCryptoAlgorithm(cryptoAlg)
                        .setDecryptPWD("changeit")
                        .setDataIN(inStream)
                        .setOutputPath(output2.getAbsolutePath());
                DataSource decrypted = util.decryptCMS(signingBean);
                util.writeToFile(decrypted, signingBean);
            }
        }
    }

    @Test
    public void encryptAndSignCMS() throws Exception {
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        InputStream input = SigningUtilTest.class.getResourceAsStream("/data/ergo.pdf");
        File output = File.createTempFile("encrcms", ".encr");
        File output2 = File.createTempFile("encrcms", ".decr");
        CertWriterReader.KeyStoreBean bean = new CertWriterReader.KeyStoreBean(keys.getSecond(), keys.getFirst());
        for (CryptoAlg cryptoAlg: CryptoAlg.values()) {
            if (cryptoAlg.getName().contains("PBE")) {
                SigningUtil util = new SigningUtil();
                SigningBean signingBean = new SigningBean()
                        .setSigningMode(SigningBean.Mode.EXPLICIT)
                        .setCryptoAlgorithm(cryptoAlg)
                        .setKeyStoreBean(bean)
                        .setDecryptPWD("changeit")
                        .setDataIN(input)
                        .setOutputPath(output.getAbsolutePath());
                Tuple<DataSource, DataSource> outCome = util.encryptAndSign(signingBean);
                util.writeToFile(outCome.getSecond(), signingBean);
                /*File inFile = new File(signingBean.getOutputPath());
                FileInputStream inStream = new FileInputStream(inFile);
                signingBean = new SigningBean()
                        .setCryptoAlgorithm(cryptoAlg)
                        .setDecryptPWD("changeit")
                        .setDataIN(inStream)
                        .setOutputPath(output2.getAbsolutePath());
                DataSource decrypted = util.decryptCMS(signingBean);
                util.writeToFile(decrypted, signingBean); */
            }
        }
    }

    @Test
    public void encryptAndSignAndDecryptReadCMS() throws Exception {
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        InputStream input = SigningUtilTest.class.getResourceAsStream("/data/ergo.pdf");
        File output = File.createTempFile("encrcms", ".encr");
        File output2 = File.createTempFile("encrcms", ".decr");
        CertWriterReader.KeyStoreBean bean = new CertWriterReader.KeyStoreBean(keys.getSecond(), keys.getFirst());
        for (CryptoAlg cryptoAlg: CryptoAlg.values()) {
            if (cryptoAlg.getName().contains("PBE")) {
                SigningUtil util = new SigningUtil();
                SigningBean signingBean = new SigningBean()
                        .setSigningMode(SigningBean.Mode.EXPLICIT)
                        .setCryptoAlgorithm(cryptoAlg)
                        .setKeyStoreBean(bean)
                        .setDecryptPWD("changeit")
                        .setDataIN(input)
                        .setOutputPath(output.getAbsolutePath());
                Tuple<DataSource, DataSource> outCome = util.encryptAndSign(signingBean);
                util.writeToFile(outCome.getSecond(), signingBean);
                File inFile = new File(signingBean.getOutputPath());
                FileInputStream inStream = new FileInputStream(inFile);
                input = SigningUtilTest.class.getResourceAsStream("/data/ergo.pdf");
                DataSource unpacked = util.unpackSignature(inStream, outCome.getFirst().getInputStream());
                signingBean = new SigningBean()
                        .setCryptoAlgorithm(cryptoAlg)
                        .setDecryptPWD("changeit")
                        .setDataIN(unpacked.getInputStream())
                        .setOutputPath(output2.getAbsolutePath());
                DataSource decrypted = util.decryptCMS(signingBean);
                util.writeToFile(decrypted, signingBean);
            }
        }
    }



}
