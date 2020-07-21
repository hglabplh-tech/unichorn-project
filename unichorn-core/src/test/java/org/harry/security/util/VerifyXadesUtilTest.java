package org.harry.security.util;

import iaik.x509.X509Certificate;
import iaik.x509.attr.AttributeCertificate;
import iaik.xml.crypto.xades.CounterSignature;
import org.harry.security.testutils.TestBase;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Enumeration;
import java.util.Optional;

public class VerifyXadesUtilTest extends TestBase {

    @Test
    public void verifySimple() throws Exception {
        File out = File.createTempFile("signed", ".xml");
        prepareSimple(out);
        VerifyXadesUtil verifier = makeVerifier(new SigningBean());
        VerificationResults.VerifierResult result = verifier.verifyXadesSignature(new FileInputStream(out), null);
        File reportFile = File.createTempFile("signed.xml", ".rep");
        ReportUtil.generateAndWriteReport(reportFile, result);
    }

    private VerifyXadesUtil makeVerifier(SigningBean bean) {
        VerifyXadesUtil util = new VerifyXadesUtil(ConfigReader.loadAllTrusts(), bean);
        return util;
    }

    private void prepareSimple(File out) throws Exception {
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        CertWriterReader.KeyStoreBean bean = new CertWriterReader.KeyStoreBean(keys.getSecond(), keys.getFirst());
        InputStream in = SignXAdESUtilTest.class.getResourceAsStream("/data/privateTrust.xml");

        SigningBean signingBean = new SigningBean().setDataIN(in)
                .setKeyStoreBean(bean)
                .setOutputPath(out.getAbsolutePath());

        InputStream p12StoreStream = VerifyXadesUtilTest.class
                .getResourceAsStream("/certificates/signing.p12");
        InputStream attrCertStream = VerifyXadesUtilTest.class
                .getResourceAsStream("/certificates/attrCert2.cer");
        AttributeCertificate attrCert = new AttributeCertificate(attrCertStream);
        KeyStore counterStore = KeyStoreTool.loadStore(p12StoreStream, "changeit".toCharArray(), "UnicP12");
        Enumeration<String> aliases = counterStore.aliases();
        Tuple<PrivateKey, X509Certificate[]> counterKeys = null;
        if (aliases.hasMoreElements()) {
            counterKeys =
                    KeyStoreTool.getKeyEntry(counterStore, aliases.nextElement(), "changeit".toCharArray());
        }
        SignXAdESUtil util = new SignXAdESUtil(bean.getSelectedKey(), bean.getChain(), false);
        SignXAdESUtil.XAdESParams params = util.newParams()
                .setTSA_URL("http://zeitstempel.dfn.de/")
                .setSetSigTimeStamp(true)
                .setAppendOCSPValues(true)
                .setSetContentTimeStamp(true)
                .setCounterSigKeys(counterKeys)
                .setSignerRole(Optional.of(attrCert));
        util.prepareSigning(signingBean.getDataIN(), params);
        util.sign(new FileOutputStream(out.getAbsolutePath()));
    }
}
