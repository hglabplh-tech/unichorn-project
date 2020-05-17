package org.harry.security.util;

import org.apache.commons.io.IOUtils;
import org.harry.security.testutils.TestBase;
import org.harry.security.util.algoritms.CryptoAlg;
import org.harry.security.util.bean.SigningBean;
import org.junit.Test;
import sun.nio.ch.IOUtil;

import javax.activation.DataSource;
import java.io.*;

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

}
