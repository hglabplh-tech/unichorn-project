package org.harry.security.util;

import org.junit.Test;

import java.io.StringWriter;
import java.io.Writer;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;

public class ServerInfoGetterTest {

    @Test
    public void testInfo() throws Exception {
        Writer writer = new StringWriter();
        ServerInfoGetter getter = new ServerInfoGetter("www.google.de", 443);
        Hashtable<iaik.x509.X509Certificate, iaik.x509.X509Certificate[]>  serverCerts = getter.getInformation();
        //System.out.println(writer.toString());
        getter = new ServerInfoGetter("www.ibm.com", 443);
        writer = new StringWriter();
        serverCerts = getter.getInformation();
        System.out.println(writer.toString());
        Enumeration<iaik.x509.X509Certificate[]> values = serverCerts.elements();
        while(values.hasMoreElements()) {
            iaik.x509.X509Certificate[] array = values.nextElement();
            for (X509Certificate cert: array) {
                iaik.x509.X509Certificate printable = new iaik.x509.X509Certificate(cert.getEncoded());
                System.out.println(printable.toString(true));
            }
        }
        //System.out.println(writer.toString());
    }
}
