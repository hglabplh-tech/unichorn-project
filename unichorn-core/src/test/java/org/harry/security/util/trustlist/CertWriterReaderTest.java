package org.harry.security.util.trustlist;

import iaik.x509.X509Certificate;
import org.harry.security.testutils.Generator;
import org.harry.security.testutils.TestBase;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;

import static junit.framework.Assert.assertNotNull;
import static junit.framework.TestCase.assertTrue;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;


public class CertWriterReaderTest extends TestBase {

    @Test
    public void readPEMTest() throws Exception {
        InputStream input =
                CertWriterReaderTest.class.getResourceAsStream("/certificates/example.pem");
        assertNotNull(input);
        CertWriterReader util = new CertWriterReader();
        X509Certificate cert = util.readFromFilePEM(input);
        assertNotNull(cert);
    }

    @Test
    public void writePEMTest() throws Exception {
        X509Certificate cert = Generator.createCertificate();
        CertWriterReader util = new CertWriterReader(cert);
        File outFile = File.createTempFile("testCert", ".pem");
        util.writeToFilePEM(new FileOutputStream(outFile));
        assertTrue("file not found", outFile.exists());
    }

    @Test
    public void writeReadPEMTest() throws Exception {
        X509Certificate cert = Generator.createCertificate();
        CertWriterReader util = new CertWriterReader(cert);
        File outFile = File.createTempFile("testCert", ".pem");
        util.writeToFilePEM(new FileOutputStream(outFile));
        assertTrue("file not found", outFile.exists());
        X509Certificate result = util.readFromFilePEM(new FileInputStream(outFile));
        assertThat("not equal",
                cert.getSubjectDN().getName(),
                is(result.getSubjectDN().getName()));
    }
}
