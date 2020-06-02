package org.harry.security.util.ocsp;

import iaik.x509.X509Certificate;
import org.harry.security.testutils.TestBase;
import org.junit.Test;

import java.io.InputStream;

public class CRLTest extends TestBase {

    @Test
    public void testGetCRLExt() throws Exception {
        InputStream certStream = CRLTest.class.getResourceAsStream("/certificates/hgp.cer");
        X509Certificate cert = new X509Certificate(certStream);
        OCSCRLPClient.getCRLOfCert(cert);


    }
}
