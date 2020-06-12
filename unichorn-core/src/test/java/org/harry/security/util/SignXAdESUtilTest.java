package org.harry.security.util;

import iaik.x509.X509Certificate;
import org.harry.security.testutils.TestBase;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;

public class SignXAdESUtilTest extends TestBase {

    @Test
    public void signSimple() throws Exception {
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        CertWriterReader.KeyStoreBean bean = new CertWriterReader.KeyStoreBean(keys.getSecond(), keys.getFirst());
        InputStream in = SignXAdESUtilTest.class.getResourceAsStream("/data/privateTrust.xml");
        File out = File.createTempFile("signed", ".xml");
        SigningBean signingBean = new SigningBean().setDataIN(in)
                .setKeyStoreBean(bean)
                .setOutputPath(out.getAbsolutePath());

        SignXAdESUtil util = new SignXAdESUtil(bean.getSelectedKey(), bean.getChain());
        SignXAdESUtil.XAdESParams params = util.newParams();
        util.prepareSigning(signingBean.getDataIN(), params);
        util.sign(new FileOutputStream(out.getAbsolutePath()));
    }
}
