package org.harry.security.util;

import iaik.pdf.cmscades.CadesSignatureStream;
import iaik.pdf.cmscades.CmsCadesException;
import iaik.x509.X509Certificate;
import iaik.x509.attr.AttributeCertificate;
import org.harry.security.testutils.Generator;
import org.harry.security.testutils.TestBase;
import org.harry.security.util.algoritms.DigestAlg;
import org.harry.security.util.algoritms.SignatureAlg;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.trustlist.TrustListManager;
import org.junit.Test;

import javax.activation.DataSource;
import javax.activation.FileDataSource;
import java.io.*;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.List;

import static junit.framework.Assert.assertNotNull;
import static junit.framework.TestCase.assertNull;
import static junit.framework.TestCase.assertTrue;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.harry.security.CommonConst.TSP_URL;


public class VerifyUtilTest extends TestBase {

    @Test
    public void quickCheckCertOK() throws Exception{
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        File out = File.createTempFile(
                "sig", "pkcs7");
        InputStream in = this.getClass().getResourceAsStream("/certificates/example.pem");
        URL url = this.getClass().getResource("/certificates/example.pem");
        File urlFile = new File(url.toURI());
        initVerifyCMS(keys.getSecond(), keys.getFirst(), out, urlFile, SigningBean.Mode.EXPLICIT);
        InputStream input = new FileInputStream(out);
        assertNotNull(input);
        in = this.getClass().getResourceAsStream("/certificates/example.pem");
        VerifyUtil.quickCheck(input, in);
    }

    @Test
    public void checkCertOKExplicit() throws Exception{
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        File out = File.createTempFile(
                "sig", "pkcs7");
        InputStream in = this.getClass().getResourceAsStream("/certificates/example.pem");
        URL url = this.getClass().getResource("/certificates/example.pem");
        File urlFile = new File(url.toURI());
        SigningBean bean = initVerifyCMS(keys.getSecond(), keys.getFirst(), out, urlFile, SigningBean.Mode.EXPLICIT);
        InputStream input = new FileInputStream(out);
        assertNotNull(input);
        in = this.getClass().getResourceAsStream("/certificates/example.pem");
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        VerifyUtil util = new VerifyUtil(walkers, bean);
        util.verifyCMSSignature(input, in);
    }

    @Test
    public void checkCertOKImplicit() throws Exception{
        X509Certificate cert = Generator.createCertificate();
        PrivateKey key = Generator.pk;
        File out = File.createTempFile(
                "sig", "pkcs7");
        InputStream in = this.getClass().getResourceAsStream("/certificates/example.pem");
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = cert;
        URL url = this.getClass().getResource("/certificates/example.pem");
        File urlFile = new File(url.toURI());
        SigningBean bean = initVerifyCMS(chain, key, out, urlFile, SigningBean.Mode.IMPLICIT);
        InputStream input = new FileInputStream(out);
        assertNotNull(input);
        in = this.getClass().getResourceAsStream("/certificates/example.pem");
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        VerifyUtil util = new VerifyUtil(walkers, bean);
        util.verifyCMSSignature(input, in);
    }

    @Test
    public void checkCertOKCAdESImplicit() throws Exception{
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        SigningUtil util = new SigningUtil();
        URL url = this.getClass().getResource("/certificates/example.pem");
        File out = File.createTempFile(
                "sig", "pkcs7");
        File urlFile = new File(url.toURI());
        InputStream in;
        SigningBean bean = initVerifyCAdES(keys.getSecond(), keys.getFirst(), out, urlFile, SigningBean.Mode.IMPLICIT, false);
        InputStream input = new FileInputStream(out);
        assertNotNull(input);
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        in = this.getClass().getResourceAsStream("/certificates/example.pem");
        VerifyUtil vutil = new VerifyUtil(walkers, bean);
        vutil.verifyCadesSignature(input, in);
    }

    @Test
    public void checkCertOKCAdESExplicit() throws Exception{
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        SigningUtil util = new SigningUtil();
        URL url = this.getClass().getResource("/certificates/example.pem");
        File out = File.createTempFile(
                "sig", "pkcs7");
        File urlFile = new File(url.toURI());
        InputStream in;
        SigningBean bean = initVerifyCAdES(keys.getSecond(), keys.getFirst(), out, urlFile, SigningBean.Mode.EXPLICIT, false);
        InputStream input = new FileInputStream(out);
        assertNotNull(input);
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        in = this.getClass().getResourceAsStream("/certificates/example.pem");
        VerifyUtil vutil = new VerifyUtil(walkers, bean);
        vutil.verifyCadesSignature(input, in);
    }

    @Test
    public void checkCertOKCAdESExplicitWithUpgrade() throws Exception{
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        SigningUtil util = new SigningUtil();
        URL url = this.getClass().getResource("/certificates/example.pem");
        File out = File.createTempFile(
                "sig", "pkcs7");
        File urlFile = new File(url.toURI());
        InputStream in;
        SigningBean bean = initVerifyCAdES(keys.getSecond(), keys.getFirst(), out, urlFile,
                SigningBean.Mode.EXPLICIT, true);
        InputStream input = new FileInputStream(out);
        assertNotNull(input);
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        in = this.getClass().getResourceAsStream("/certificates/example.pem");
        VerifyUtil vutil = new VerifyUtil(walkers, bean);
        vutil.verifyCadesSignature(input, in);
    }



    @Test
    public void detectChainTest() {
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        SigningBean bean = new SigningBean();
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        VerifyUtil vutil = new VerifyUtil(walkers, bean);
        AlgorithmPathChecker pathChecker = new AlgorithmPathChecker(walkers, bean);
        VerifyUtil.SignerInfoCheckResults results = new VerifyUtil.SignerInfoCheckResults();
        X509Certificate[] chain = pathChecker.detectChain(keys.getSecond()[0], results);
        int index = 0;
        for (X509Certificate cert: chain) {
            X509Certificate other = keys.getSecond()[index];
            System.out.println(cert.getSubjectDN().getName());
            System.out.println(other.getSubjectDN().getName());
            index++;
        }

    }

    @Test
    public void checkArchiveTimestamp() throws Exception {
        InputStream data = this.getClass().getResourceAsStream("/data/pom.xml");
        InputStream signature =this.getClass().getResourceAsStream("/data/pom.xml.pkcs7");
        assertNotNull("signature is null", signature);
        assertNotNull("data is null", data);
        CadesSignatureStream sigData = getSignature(signature, data);
        SigningBean bean = new SigningBean();
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        VerifyUtil vutil = new VerifyUtil(walkers, bean);
        VerifyUtil.SignerInfoCheckResults results = new VerifyUtil.SignerInfoCheckResults();
        vutil.cadesExtractTimestampAndData(results, sigData);
    }


    private SigningBean initVerifyCMS(X509Certificate[] cert, PrivateKey key,
                                      File out, File in, SigningBean.Mode signingMode) throws Exception {
        SigningUtil util = new SigningUtil();
        InputStream input = VerifyUtilTest.class.getResourceAsStream("/certificates/attrCert2.cer");
        AttributeCertificate attrCert = new AttributeCertificate(input);
        CertWriterReader.KeyStoreBean keys = new CertWriterReader.KeyStoreBean(cert,key);
        SigningBean bean = new SigningBean().setDataINFile(in)
                .setAttributeCertificate(attrCert)
                .setDataIN(new FileInputStream(in))
                .setOutputPath(out.getAbsolutePath())
                .setOutputDS(new FileDataSource(out))
                .setKeyStoreBean(keys)
                .setDigestAlgorithm(DigestAlg.SHA3_512)
                .setSignatureAlgorithm(SignatureAlg.SHA3_512_WITH_RSA)
                .setSigningMode(signingMode);
        DataSource ds = util.signCMS(bean);
        util.writeToFile(ds, bean);
        return bean;
    }

    private SigningBean initVerifyCAdES(X509Certificate[] cert, PrivateKey key,
                                        File out, File in, SigningBean.Mode signingMode, boolean upgrade) throws Exception {
        SigningUtil util = new SigningUtil();
        InputStream input = VerifyUtilTest.class.getResourceAsStream("/certificates/attrCert2.cer");
        AttributeCertificate attrCert = new AttributeCertificate(input);
        CertWriterReader.KeyStoreBean keys = new CertWriterReader.KeyStoreBean(cert,key);
        SigningBean bean = new SigningBean().setDataINFile(in)
                .setAttributeCertificate(attrCert)
                .setTspURL("http://zeitstempel.dfn.de")
                //.setTspURL(TSP_URL)
                .setDataIN(new FileInputStream(in))
                .setDigestAlgorithm(DigestAlg.SHA3_512)
                .setSignatureAlgorithm(SignatureAlg.SHA3_512_WITH_RSA)
                .setOutputPath(out.getAbsolutePath())
                .setOutputDS(new FileDataSource(out))
                .setKeyStoreBean(keys)
                .setDigestAlgorithm(DigestAlg.SHA3_512)
                .setSignatureAlgorithm(SignatureAlg.SHA3_512_WITH_RSA)
                .setSigningMode(signingMode);
        DataSource ds = util.signCAdES(bean, false);
        util.writeToFile(ds, bean);
        return bean;
    }

    private SigningBean setBean(X509Certificate[] cert, PrivateKey key, File out, File in, boolean setTSA) throws Exception {
        CertWriterReader.KeyStoreBean keys = new CertWriterReader.KeyStoreBean(cert,key);
        InputStream inputCert = VerifyUtilTest.class.getResourceAsStream("/certificates/attrCert2.cer");
        AttributeCertificate attrCert = new AttributeCertificate(inputCert);
        FileInputStream input = new FileInputStream(in);
        SigningBean bean = new SigningBean()
                .setAttributeCertificate(attrCert)
                .setSigningMode(SigningBean.Mode.EXPLICIT)
                .setDataIN(input)
                .setDataINFile(in).setOutputPath(out.getAbsolutePath())
                .setDataINPath(in)
                .setOutputDS(new FileDataSource(out))
                .setKeyStoreBean(keys)
                .setSigningMode(SigningBean.Mode.EXPLICIT);
        if (setTSA) {
            bean = bean.setTspURL("http://zeitstempel.dfn.de");
        }
        return bean;

    }

    private CadesSignatureStream getSignature(InputStream signature, InputStream data) throws CmsCadesException {
        CadesSignatureStream sigStream = new CadesSignatureStream(signature, data);
        return sigStream;
    }
}
