package org.harry.security.util;

import org.junit.Test;
import org.pmw.tinylog.writers.ConsoleWriter;

import java.io.Console;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;

public class ServerInfoGetterTest {

    @Test
    public void testInfo() throws Exception {
        Writer writer = new StringWriter();
        ServerInfoGetter getter = new ServerInfoGetter("www.google.de", 443, writer, "");
        Hashtable<X509Certificate, X509Certificate[]>  serverCerts = getter.showInfo();
        //System.out.println(writer.toString());
        getter = new ServerInfoGetter("www.ibm.com", 443, writer, "");
        writer = new StringWriter();
        serverCerts = getter.showInfo();
        System.out.println(writer.toString());
        Enumeration<X509Certificate[]> values = serverCerts.elements();
        while(values.hasMoreElements()) {
            X509Certificate[] array = values.nextElement();
            for (X509Certificate cert: array) {
                iaik.x509.X509Certificate printable = new iaik.x509.X509Certificate(cert.getEncoded());
                System.out.println(printable.toString(true));
            }
        }
        //System.out.println(writer.toString());
    }
}
