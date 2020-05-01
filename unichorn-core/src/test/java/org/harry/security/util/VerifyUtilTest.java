package org.harry.security.util;

import iaik.x509.X509Certificate;
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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.List;

import static junit.framework.Assert.assertNotNull;
import static junit.framework.TestCase.assertTrue;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;




public class VerifyUtilTest extends TestBase {

    @Test
    public void quickCheckCertOK() throws Exception{
        X509Certificate cert = Generator.createCertificate();
        PrivateKey key = Generator.pk;
        File out = File.createTempFile(
                "sig", "pkcs7");
        InputStream in = this.getClass().getResourceAsStream("/certificates/example.pem");
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = cert;
        URL url = this.getClass().getResource("/certificates/example.pem");
        File urlFile = new File(url.toURI());
        initVerify(chain, key, out, urlFile);
        InputStream input = new FileInputStream(out);
        assertNotNull(input);
        in = this.getClass().getResourceAsStream("/certificates/example.pem");
        VerifyUtil.quickCheck(input, in);
    }

    @Test
    public void checkCertOK() throws Exception{
        X509Certificate cert = Generator.createCertificate();
        PrivateKey key = Generator.pk;
        File out = File.createTempFile(
                "sig", "pkcs7");
        InputStream in = this.getClass().getResourceAsStream("/certificates/example.pem");
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = cert;
        URL url = this.getClass().getResource("/certificates/example.pem");
        File urlFile = new File(url.toURI());
        SigningBean bean = initVerify(chain, key, out, urlFile);
        InputStream input = new FileInputStream(out);
        assertNotNull(input);
        in = this.getClass().getResourceAsStream("/certificates/example.pem");
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        VerifyUtil util = new VerifyUtil(walkers, bean);
        util.verifyCMSSignature(input, in);
    }

    @Test
    public void checkCertOKCAdES() throws Exception{
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        SigningUtil util = new SigningUtil();
        File out = File.createTempFile(
                "sig", "pkcs7");
        //
        // InputStream in = this.getClass().getResourceAsStream("/certificates/example.pem");
        URL url = this.getClass().getResource("/certificates/example.pem");
        File urlFile = new File(url.toURI());
        FileInputStream in = new FileInputStream(urlFile);
        SigningBean bean = setBean(keys.getSecond(), keys.getFirst(), out, urlFile, true);
        DataSource ds = util.signCAdES(bean, true);
        bean = setBean(keys.getSecond(), keys.getFirst(), out, urlFile, false);
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        VerifyUtil vutil = new VerifyUtil(walkers, bean);
        vutil.verifyCadesSignature(ds.getInputStream(), in);
    }


    private SigningBean initVerify(X509Certificate[] cert, PrivateKey key, File out, File in) {
        SigningUtil util = new SigningUtil();
        CertWriterReader.KeyStoreBean keys = new CertWriterReader.KeyStoreBean(cert,key);
        SigningBean bean = new SigningBean().setDataINFile(in).setOutputPath(out.getAbsolutePath())
                .setOutputDS(new FileDataSource(out))
                .setKeyStoreBean(keys)
                .setDigestAlgorithm(DigestAlg.SHA3_512)
                .setSignatureAlgorithm(SignatureAlg.SHA3_512_WITH_RSA)
                .setSigningMode(SigningBean.Mode.EXPLICIT);
        DataSource ds = util.signCMS(bean);
        util.writeToFile(ds, bean);
        return bean;
    }

    private SigningBean setBean(X509Certificate[] cert, PrivateKey key, File out, File in, boolean setTSA) throws FileNotFoundException {
        CertWriterReader.KeyStoreBean keys = new CertWriterReader.KeyStoreBean(cert,key);

        FileInputStream input = new FileInputStream(in);
        SigningBean bean = new SigningBean()
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
}
