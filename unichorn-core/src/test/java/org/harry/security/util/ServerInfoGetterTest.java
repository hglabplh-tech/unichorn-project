package org.harry.security.util;

import iaik.security.ssl.SSLClientContext;
import org.junit.Test;

import java.io.StringWriter;
import java.io.Writer;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;

public class ServerInfoGetterTest {

    @Test
    public void testInfo() throws Exception {
        List<String> serversToCheck = Arrays.asList("www.ibm.com", "www.digicert.com", "www.google.de", "www.commerzbank.de");
        Writer writer = new StringWriter();
        for (String server : serversToCheck) {
            Hashtable<iaik.x509.X509Certificate, iaik.x509.X509Certificate[]> serverCerts;

            ServerInfoGetter getter = new ServerInfoGetter(server, 443);
            writer = new StringWriter();
            serverCerts = getter.getInformation();
            SSLClientContext clientContext = getter.freshContext();
            ServerInfoGetter.CertStatusValue result = getter.ocspCheckStapling(server, 443, clientContext);
            if (result.equals(ServerInfoGetter.CertStatusValue.STATUS_OK)) {
                System.out.println("OCSP check already successfully using stapling");
            } else if (result.equals(ServerInfoGetter.CertStatusValue.STATUS_NOK)) {
                System.out.println("OCSP check already successfully using stapling bot NOT OK");
            } else {
                System.out.println("OCSP check could not be processed");
            }
            System.out.println(writer.toString());
            Enumeration<iaik.x509.X509Certificate[]> values = serverCerts.elements();
            while (values.hasMoreElements()) {
                iaik.x509.X509Certificate[] array = values.nextElement();
                for (X509Certificate cert : array) {
                    iaik.x509.X509Certificate printable = new iaik.x509.X509Certificate(cert.getEncoded());
                    System.out.println(printable.toString(true));
                }
            }
            //System.out.println(writer.toString());
        }
    }
}
