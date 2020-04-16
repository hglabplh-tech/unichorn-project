package org.harry.security.util;

import iaik.x509.X509Certificate;
import org.harry.security.testutils.Generator;
import org.harry.security.testutils.TestBase;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.trustlist.TrustListWalkerAndGetter;
import org.junit.Test;

import javax.activation.DataSource;
import javax.activation.FileDataSource;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
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
        initVerify(cert, key, out, in);
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
        SigningBean bean = initVerify(cert, key, out, in);
        InputStream input = new FileInputStream(out);
        assertNotNull(input);
        in = this.getClass().getResourceAsStream("/certificates/example.pem");
        List<TrustListWalkerAndGetter> walkers = ConfigReader.loadAllTrusts();
        VerifyUtil util = new VerifyUtil(walkers, bean);
        util.verifyCMSSignature(input, in);
    }

    private SigningBean initVerify(X509Certificate cert, PrivateKey key, File out, InputStream in) {
        SigningUtil util = new SigningUtil();
        SigningUtil.KeyStoreBean keys = new SigningUtil.KeyStoreBean(cert,key);
        SigningBean bean = new SigningBean().setDataIN(in).setOutputPath(out.getAbsolutePath())
                .setOutputDS(new FileDataSource(out))
                .setKeyStoreBean(keys)
                .setSigningMode(SigningBean.Mode.EXPLICIT);
        DataSource ds = util.signCMS(bean);
        util.writeToFile(ds, bean);
        return bean;
    }
}
