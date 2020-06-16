package org.harry.security.util;

import iaik.asn1.ObjectID;
import iaik.x509.X509Certificate;
import iaik.x509.attr.AttributeCertificate;
import org.apache.commons.io.IOUtils;
import org.harry.security.testutils.TestBase;
import org.harry.security.util.algoritms.CryptoAlg;
import org.harry.security.util.algoritms.DigestAlg;
import org.harry.security.util.algoritms.SignatureAlg;
import org.harry.security.util.bean.AttrCertBean;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.trustlist.TrustListManager;
import org.junit.Test;


import javax.activation.DataSource;
import java.io.*;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Enumeration;
import java.util.List;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.harry.security.CommonConst.TSP_URL;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

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
    public void counterSignASignatureCMS() throws Exception {
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        URL urlInput = SigningUtilTest.class.getResource("/data/ergo.pdf");
        File fileInput = new File(urlInput.toURI());
        File output = File.createTempFile("signedCMS", ".pkcs7");
        CertWriterReader.KeyStoreBean bean = new CertWriterReader.KeyStoreBean(keys.getSecond(), keys.getFirst());
        SigningUtil util = new SigningUtil();
        SigningBean signingBean = new SigningBean()
                .setSigningMode(SigningBean.Mode.EXPLICIT)
                .setDigestAlgorithm(DigestAlg.SHA3_512)
                .setSignatureAlgorithm(SignatureAlg.SHA3_512_WITH_RSA)
                .setKeyStoreBean(bean)
                .setDecryptPWD("changeit")
                .setDataIN(new FileInputStream(fileInput))
                .setOutputPath(output.getAbsolutePath());
        DataSource outCome = util.signCMS(signingBean);
        util.writeToFile(outCome, signingBean);
        File counterOutput = File.createTempFile("counterSignedCMS", ".pkcs7");
        signingBean = new SigningBean()
                .setSigningMode(SigningBean.Mode.EXPLICIT)
                .setDigestAlgorithm(DigestAlg.SHA3_512)
                .setSignatureAlgorithm(SignatureAlg.SHA3_512_WITH_RSA)
                .setKeyStoreBean(bean)
                .setDecryptPWD("changeit")
                .setDataINFile(fileInput)
                .setDataIN(new FileInputStream(output))
                .setOutputPath(counterOutput.getAbsolutePath());
        outCome = util.setCounterSignature(signingBean);
        util.writeToFile(outCome, signingBean);
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        VerifyUtil vutil = new VerifyUtil(walkers, signingBean);
        vutil.verifyCadesSignature(new FileInputStream(counterOutput), new FileInputStream(fileInput));

    }

    @Test
    public void counterSignASignatureCAdES() throws Exception {
        KeyStore store = KeyStoreTool.loadAppStore();
        InputStream counterKeyInput = SigningUtilTest.class.getResourceAsStream("/certificates/signing.p12");
        KeyStore counterStore = KeyStoreTool.loadStore(counterKeyInput, "changeit".toCharArray(), "PKCS12");
        Enumeration<String> aliases = counterStore.aliases();
        Tuple<PrivateKey, X509Certificate[]> counterKeys = null;
        if (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            counterKeys =
                    KeyStoreTool.getKeyEntry(counterStore, alias, "changeit".toCharArray());
        } else {
            fail("no keys found for counter sign");
        }
        assertNotNull(counterKeys);
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        URL urlInput = SigningUtilTest.class.getResource("/data/ergo.pdf");
        File fileInput = new File(urlInput.toURI());
        File output = File.createTempFile("signedCMS", ".pkcs7");
        CertWriterReader.KeyStoreBean bean = new CertWriterReader.KeyStoreBean(keys.getSecond(), keys.getFirst());
        CertWriterReader.KeyStoreBean counterBean =
                new CertWriterReader.KeyStoreBean(counterKeys.getSecond(), counterKeys.getFirst());
        SigningUtil util = new SigningUtil();
        SigningBean signingBean = new SigningBean()
                .setTspURL("http://zeitstempel.dfn.de")
                .setSigningMode(SigningBean.Mode.EXPLICIT)
                .setKeyStoreBean(bean)
                .setDecryptPWD("changeit")
                .setDataIN(new FileInputStream(fileInput))
                .setOutputPath(output.getAbsolutePath());
        DataSource outCome = util.signCAdES(signingBean, false);
        util.writeToFile(outCome, signingBean);
        File counterOutput = File.createTempFile("counterSignedCMS", ".pkcs7");
        signingBean = new SigningBean()
                .setSigningMode(SigningBean.Mode.EXPLICIT)
                .setDigestAlgorithm(DigestAlg.SHA3_512)
                .setSignatureAlgorithm(SignatureAlg.SHA3_512_WITH_RSA)
                .setKeyStoreBean(bean)
                .setCounterKeyStoreBean(counterBean)
                .setDecryptPWD("changeit")
                .setDataINFile(fileInput)
                .setDataIN(new FileInputStream(output))
                .setOutputPath(counterOutput.getAbsolutePath());
        outCome = util.setCounterSignature(signingBean);
        util.writeToFile(outCome, signingBean);
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        VerifyUtil vutil = new VerifyUtil(walkers, signingBean);
        vutil.verifyCadesSignature(new FileInputStream(counterOutput), new FileInputStream(fileInput));
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
        File output = File.createTempFile("countersigned", ".pkcs7");
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
