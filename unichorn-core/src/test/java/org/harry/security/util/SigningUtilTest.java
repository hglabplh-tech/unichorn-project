package org.harry.security.util;

import iaik.x509.X509Certificate;
import iaik.x509.attr.AttributeCertificate;
import org.apache.commons.io.IOUtils;
import org.harry.security.testutils.TestBase;
import org.harry.security.util.algoritms.CryptoAlg;
import org.harry.security.util.bean.AttrCertBean;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.junit.Test;


import javax.activation.DataSource;
import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

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

    @Test
    public void signWithAttributCertificateCMS() throws Exception {
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        InputStream input = SigningUtilTest.class.getResourceAsStream("/data/ergo.pdf");
        File output = File.createTempFile("encrcms", ".pkcs7");
        CertWriterReader.KeyStoreBean bean = new CertWriterReader.KeyStoreBean(keys.getSecond(), keys.getFirst());
        SigningUtil util = new SigningUtil();
        SigningBean signingBean = new SigningBean()
                .setAttributeCertificate(createAttributeCert())
                .setSigningMode(SigningBean.Mode.EXPLICIT)
                .setKeyStoreBean(bean)
                .setDecryptPWD("changeit")
                .setDataIN(input)
                .setOutputPath(output.getAbsolutePath());
        DataSource outCome = util.signCMS(signingBean);
        util.writeToFile(outCome, signingBean);
    }

    @Test
    public void signWithAttributCertificateCAdES() throws Exception {
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        InputStream input = SigningUtilTest.class.getResourceAsStream("/data/ergo.pdf");
        File output = File.createTempFile("encrcms", ".pkcs7");
        CertWriterReader.KeyStoreBean bean = new CertWriterReader.KeyStoreBean(keys.getSecond(), keys.getFirst());

        SigningUtil util = new SigningUtil();
        SigningBean signingBean = new SigningBean()
                .setAttributeCertificate(createAttributeCert())
                .setSigningMode(SigningBean.Mode.EXPLICIT)
                .setKeyStoreBean(bean)
                .setDecryptPWD("changeit")
                .setDataIN(input)
                .setOutputPath(output.getAbsolutePath());
        DataSource outCome = util.signCAdES(signingBean, false);
        util.writeToFile(outCome, signingBean);


    }



    private AttributeCertificate createAttributeCert() {
        String[] targetnames = new String[]{"Unichorn Team 1", "Unichorn Team 2", "Unichorn Team 3", "Unichorn Team 4"};
        AttrCertBean attrBean = new AttrCertBean()
                .setRoleName("urn:signer")
                .setCommonName("Common Signer Author")
                .setTargetName("Unichorn Signer")
                .setTargetNames(targetnames)
                .setTargetGroup("Unichorn Signing Group")
                .setAuthCountry("DE")
                .setAuthOrganization("Unichorn Signing GmbH")
                .setAuthOrganizationalUnit("Unichorn Signing Development Team")
                .setAuthCommonName("Unichorn Signers Group")
                .setCategory("signing")
                .setAccessIdentityService("www.unichorn-signing.de")
                .setAccessIdentityIdent("signingId")
                .setGroupValue1("Developers Certificates 1")
                .setGroupValue2("Developers Certificates 2");
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        AttributeCertificate attrCert = CertificateWizzard.createAttributeCertificate(keys.getSecond()[0],
                keys.getSecond()[0],
                keys.getFirst(),
                attrBean);
        assertThat(attrCert, is(notNullValue()));

        return attrCert;
    }



}
