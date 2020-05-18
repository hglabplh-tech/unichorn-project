package org.harry.security.util;

import org.harry.security.util.bean.SigningBean;
import org.junit.Test;

import javax.activation.DataSource;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;

public class CMSCompressUtilTest {

    @Test
    public void bothDirections() throws Exception {
        InputStream input = this.getClass().getResourceAsStream("/data/pom.xml");
        File outFile = File.createTempFile("data", ".cms");
        File decompFile = File.createTempFile("data", ".out");
        SigningBean signingBean = new SigningBean()
                .setOutputPath(outFile.getAbsolutePath())
                .setDataIN(input);
        DataSource result = CMSCompressUtil.compressDataStreamCMS(signingBean);
        SigningUtil util = new SigningUtil();
        util.writeToFile(result, signingBean);
        FileInputStream compressed = new FileInputStream(outFile);
        signingBean = new SigningBean()
                .setDataIN(compressed)
        .setOutputPath(decompFile.getAbsolutePath());
        DataSource decompressed = CMSCompressUtil.decompressDataStreamCMS(signingBean);
        util.writeToFile(decompressed, signingBean);

    }
}
