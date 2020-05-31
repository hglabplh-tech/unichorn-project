package org.harry.security.util;

import iaik.security.ssl.*;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;

public class ServerInfoGetter {


    private final static int SOCKET_TIMEOUT = 15*1000; // 15 seconds

    private final static int VERSION_SSL20 = SSLContext.VERSION_SSL20;
    private final static int VERSION_SSL30 = SSLContext.VERSION_SSL30;
    private final static int VERSION_TLS10 = SSLContext.VERSION_TLS10;
    private final static int VERSION_TLS11 = SSLContext.VERSION_TLS11;
    private final static int VERSION_TLS12 = SSLContext.VERSION_TLS12;
    private final static int VERSION_TLS13 = SSLContext.VERSION_TLS13;

    private final static int[] VERSIONS = {
            VERSION_SSL30,
            VERSION_TLS10,
            VERSION_TLS11,
            VERSION_TLS12,
            VERSION_TLS13
    };

    private String hostname;
    private int port;
    private PrintWriter writer;
    private String backUrl;

    private InetAddress hostAddress;
    private SSLClientContext context;
    private boolean okSSL2, okSSL3, okTLS10, okTLS11, okTLS12, okTLS13;
    private String serverId;
    private Throwable exception;
    private CipherSuiteList v2Suites;
    private java.security.cert.X509Certificate v2Cert;
    private Hashtable<java.security.cert.X509Certificate, java.security.cert.X509Certificate[]> serverCerts;
    private boolean eccAvailable;

    public ServerInfoGetter(String hostname, int port, Writer w, String backUrl) {
        this.hostname = hostname;
        this.port = port;
        this.writer = new PrintWriter(w);
        context = new SSLClientContext();
        context.setSessionManager(null);            // no session caching
        context.setChainVerifier(null);             // no certificate verifying at all
        // allow legacy renegotiation
        context.setAllowLegacyRenegotiation(true);
        // ECC available?
        SecurityProvider iaikEccProvider = null;
        try {
            iaikEccProvider = IaikSSLUtil.getEccSecurityProvider();
            // install ECC provider
            SecurityProvider.setSecurityProvider(iaikEccProvider);
            eccAvailable = true;
        } catch (Exception e) {
            // ignore; iaikEccProvider is null
        }
        serverCerts = new Hashtable<java.security.cert.X509Certificate, java.security.cert.X509Certificate[]>();
    }

    private void setExtensions(SSLContext context) {

        ExtensionList extensions = new ExtensionList();
        if (eccAvailable) {
            extensions.addExtension(new iaik.security.ssl.SupportedEllipticCurves());
            extensions.addExtension(new iaik.security.ssl.SupportedPointFormats());
        }
        int[] allowedVersions = context.getAllowedProtocolVersions();

        if (allowedVersions[1] >= SSLContext.VERSION_TLS10) {
            SignatureSchemeList supportedSignatureAlgorithms = (SignatureSchemeList)SignatureAndHashAlgorithmList.getDefault();
            SignatureAlgorithms signatureAlgorithms = new SignatureAlgorithms(supportedSignatureAlgorithms);
            extensions.addExtension(signatureAlgorithms);
        }
        context.setExtensions(extensions);

    }

    /**
     * Get the SSL information of a given host
     * @return the SSL certificates HashTable
     */
    public Hashtable<java.security.cert.X509Certificate, java.security.cert.X509Certificate[]> getInformation() {

        if (hostname.indexOf("<") != -1) {
            // do not echo hostname (XSS)
            hostname = null;
        }

        String title = "SSL/TLS Server Information";
        writer.println("<HTML><HEAD><TITLE>");
        writer.println(title);
        writer.println("</TITLE></HEAD><BODY>");

        writer.println("<H1>");
        writer.println(title);
        writer.println("</H1>");

        String time = new Date().toString();
        writer.println("Starting report generation at " + time);
        writeLine();

        writeEM("Resolving hostname...");
        if (hostname != null) {
            try {
                hostAddress = InetAddress.getByName(hostname);
            } catch( UnknownHostException e ) {
                // do not echo hostname (XSS)
                hostname = null;
            }
        }

        if (hostname == null) {
            writer.println("<p>Could not resolve host!</p>");
            writeFooter();
            return serverCerts;
        }

        writer.println("IP address for server is " + hostAddress.getHostAddress());
        writeLine();

        SSLSocket socket = null;

        CipherSuiteList initialCipherSuites = new CipherSuiteList(CipherSuiteList.L_IMPLEMENTED);
        CipherSuiteList cipherSuites = new CipherSuiteList(CipherSuiteList.L_IMPLEMENTED);
        CipherSuiteList notSupportedCipherSuites = new CipherSuiteList();

        initialCipherSuites.add(CipherSuite.PRIVATE_RSA_WITH_RC2_CBC_MD5);
        context.setEnabledCipherSuiteList(initialCipherSuites);

        Hashtable supportedKeyExchange = new Hashtable();
        Hashtable supportedCiphers = new Hashtable();
        for(Enumeration e = cipherSuites.elements(); e.hasMoreElements(); ) {
            CipherSuite next = (CipherSuite)e.nextElement();
            HtmlUtil.addCipherSuite(next, supportedKeyExchange, supportedCiphers, false);
        }

        writeEM("Connecting to " + hostname + ":" + port + "...");
        try {
            socket = new SSLSocket(hostAddress, port, context);
            socket.setSoTimeout(SOCKET_TIMEOUT);
        } catch( IOException e ) {
            writeStackTrace("Connection failed, there does not seem to be a server running!", e);
            writeFooter();
            IaikSSLUtil.close(socket);
            return serverCerts;
        }
        writer.println("TCP connection established.");
        writeLine();

        writeEM("Starting SSLv3/TLS handshake...");
        writer.println("<BLOCKQUOTE><PRE>");
        context.setAllowedProtocolVersions(VERSION_SSL30, VERSION_TLS13);
        socket.setDebugStream(writer);
        boolean ok = tryConnect(socket);
        writer.println("</PRE></BLOCKQUOTE>");
        if( ok ) {
            writer.println("SSL/TLS connect successful.");
        } else {
            writeStackTrace("SSL/TLS connect failed:", exception);
        }
        writeLine();
        if( writer.checkError() ) {
            return serverCerts;
        }

        writeEM("Checking for TLS 1.3 support...");
        if( okTLS13 ) {
            writer.println("TLS 1.3 is supported by this server.");
        } else {
            writer.println("TLS 1.3 is NOT supported by this server.");
        }

        writeEM("Checking for TLS 1.2 support...");
        if( okTLS12 == false ) {
            context.setAllowedProtocolVersions(VERSION_TLS12, VERSION_TLS12);
            tryConnect(null);
        }
        if( okTLS12 ) {
            writer.println("TLS 1.2 is supported by this server.");
        } else {
            writer.println("TLS 1.2 is NOT supported by this server.");
        }

        writeEM("Checking for TLS 1.1 support...");
        if( okTLS11 == false ) {
            context.setAllowedProtocolVersions(VERSION_TLS11, VERSION_TLS11);
            tryConnect(null);
        }
        if( okTLS11 ) {
            writer.println("TLS 1.1 is supported by this server.");
        } else {
            writer.println("TLS 1.1 is NOT supported by this server.");
        }

        writeEM("Checking for TLS 1.0 support...");
        if( okTLS10 == false ) {
            context.setAllowedProtocolVersions(VERSION_TLS10, VERSION_TLS10);
            tryConnect(null);
        }
        if( okTLS10 ) {
            writer.println("TLS 1.0 is supported by this server.");
        } else {
            writer.println("TLS 1.0 is NOT supported by this server.");
        }
        writeLine();

        writeEM("Checking for SSLv3 support...");
        if( okSSL3 == false ) {
            context.setAllowedProtocolVersions(VERSION_SSL30, VERSION_SSL30);
            tryConnect(null);
        }
        if( okSSL3 ) {
            writer.println("SSLv3 is supported by this server.");
        } else {
            writer.println("SSLv3 is NOT supported by this server.");
        }
        writeLine();
        if( writer.checkError() ) {
            return serverCerts;
        }

        writeEM("Checking for SSLv2 support...");
        if( okSSL2 == false ) {
            context.setAllowedProtocolVersions(VERSION_SSL20, VERSION_SSL20);
            tryConnect(null);
        }
        if( okSSL2 ) {
            writer.println("SSLv2 is supported by this server.");
        } else {
            writer.println("SSLv2 is NOT supported by this server.");
        }
        writeLine();
        if( writer.checkError() ) {
            return serverCerts;
        }

        writeEM("Server name returned in HTTP request:");
        if( serverId == null ) {
            writer.println("(none)");
        } else {
            writer.println(serverId);
        }
        writeLine();



        if( okSSL2 ) {

            writer.println("<H3>SSLv2 Summary</H3>");

            writeEM("SSLv2 ciphersuites supported by this server:");
            writer.println("<BLOCKQUOTE><PRE>");
            HtmlUtil.printCipherSuiteList(writer, v2Suites);
            writer.println("</PRE></BLOCKQUOTE>");

            writeEM("SSLv2 ciphersuites NOT supported by this server:");
            writer.println("<BLOCKQUOTE><PRE>");
            CipherSuiteList v2All = new CipherSuiteList(CipherSuite.CS_SSL_V2);
            v2All.remove(v2Suites.toArray());
            HtmlUtil.printCipherSuiteList(writer, v2All);
            writer.println("</PRE></BLOCKQUOTE>");

            writer.println("<H2>RSA Server Certificate</H2>");
            HtmlUtil.printCertificate(writer, v2Cert);
        }

        writeEM("Checking server supported SSLv3/TLS ciphersuites (this may take a while)...");
        writer.println("<BLOCKQUOTE><PRE>");

        int size = cipherSuites.size();
        int i = 0;
        boolean certAdded = false;
        while (i < size) {
            CipherSuite suite = null;
            try {
                suite = cipherSuites.elementAt(i++);
                int maxVersion = suite.getAllowedMaxVersion();
                int minVersion = suite.getAllowedMinVersion();
                int version = -1;


                for (int v = VERSIONS.length-1; v > 0; v--) {
                    int ver = VERSIONS[v];
                    if ((ver <= maxVersion) && (ver >= minVersion)) {
                        switch (ver) {
                            case VERSION_TLS13 :
                                if (okTLS13) version = ver;
                                break;
                            case VERSION_TLS12 :
                                if (okTLS12) version = ver;
                                break;
                            case VERSION_TLS11 :
                                if (okTLS11) version = ver;
                                break;
                            case VERSION_TLS10 :
                                if (okTLS10) version = ver;
                                break;
                            case VERSION_SSL30 :
                                if (okSSL3) version = ver;
                                break;
                            default :
                                break;
                        };
                    }
                    if (version != -1) {
                        break;
                    }

                }
                if (version == -1) {
                    suite = null;
                    continue;
                }
                context.setAllowedProtocolVersions(maxVersion, maxVersion);
                setExtensions(context);
                context.setEnabledCipherSuites(new CipherSuite[] { suite });
                try {
                    context.updateCipherSuites();
                } catch (Exception e) {
                    continue;
                }
                socket = new SSLSocket(hostAddress, port, context);
                socket.setSoTimeout(SOCKET_TIMEOUT);
                socket.startHandshake();
                CipherSuite active = socket.getActiveCipherSuite();
                writer.println(active.getName());
                if( writer.checkError() ) {
                    return serverCerts;
                }
                //   cipherSuites.remove(active);

                HtmlUtil.addCipherSuite(active, supportedKeyExchange, supportedCiphers, true);
            } catch( IOException e ) {
                // handshake error (typically no common ciphersuites)
                notSupportedCipherSuites.add(suite);
                // break;
            } finally {
                if (suite != null) {
                    if (!certAdded) {
                        java.security.cert.X509Certificate[] certs = socket.getPeerCertificateChain();
                        if (certs != null) {
                            try {
                                addCertificates(certs);
                            } catch (CertificateException e) {
                                e.printStackTrace();
                            }
                            certAdded = true;
                        }
                    }
                    IaikSSLUtil.close(socket);
                }
            }
        }
        writer.println("</PRE></BLOCKQUOTE>");

        writeEM("SSLv3/TLS ciphersuites NOT supported or not enabled by this server:");
        writer.println("<BLOCKQUOTE><PRE>");
        HtmlUtil.printCipherSuiteList(writer, notSupportedCipherSuites);
        writer.println("</PRE></BLOCKQUOTE>");

        HtmlUtil.writeNameAndValues(writer, "Supported cipher algorithms", supportedCiphers);
        HtmlUtil.writeNameAndValues(writer, "Supported key exchange algorithms", supportedKeyExchange);

        for(Enumeration<java.security.cert.X509Certificate[]> e = serverCerts.elements(); e.hasMoreElements(); ) {
            java.security.cert.X509Certificate[] next = e.nextElement();
            String type = Utils.certTypeToString(Utils.getCertificateType(next));
            HtmlUtil.printCertificateChain(writer, type + " Certificate Chain", next);
        }

        writeLine();
        writeFooter();
        return serverCerts;
    }

    /**
     * add the server certificates to the hash-table
     * @param certs certificates to add
     * @throws CertificateException
     */
    private void addCertificates(java.security.cert.X509Certificate[] certs) throws CertificateException {
        if( certs == null ) {
            return;
        }
        X509Certificate[] certIAIK = Util.convertCertificateChain(certs);
        for (X509Certificate thisCert: certIAIK) {
            System.out.println(thisCert.toString(true));
        }
        serverCerts.put(certs[0], certs);
    }

    /**
     * connect to a socket and gedt the protocol version
     * @param socket the socket
     * @return
     */
    private boolean tryConnect(SSLSocket socket) {
        try {

            if( socket == null ) {
                socket = new SSLSocket(hostAddress, port, context);
                socket.setSoTimeout(SOCKET_TIMEOUT);
            }
            socket.startHandshake();
            int version = socket.getActiveProtocolVersion();
            if( version == VERSION_TLS13 ) {
                okTLS13 = true;
            } else if( version == VERSION_TLS12 ) {
                okTLS12 = true;
            } else if( version == VERSION_TLS11 ) {
                okTLS11 = true;
            } else if( version == VERSION_TLS10 ) {
                okTLS10 = true;
            } else if( version == VERSION_SSL30 ) {
                okSSL3 = true;
            } else if( version == VERSION_SSL20 ) {
                if( okSSL2 == false ) {
                    okSSL2 = true;
                    v2Suites = socket.getPeerSupportedCipherSuiteList();
                    v2Cert = socket.getPeerCertificateChain()[0];
                }
            } else {
                throw new IOException("Internal version error");
            }
            socket.setDebugStream((PrintStream)null);
            getServerId(socket);
            return true;
        } catch( IOException e ) {
            exception = e;
            return false;
        } finally {
            if( socket != null ) {
                socket.setDebugStream((PrintStream)null);
            }
            IaikSSLUtil.close(socket);
            socket = null;
        }
    }

    /**
     * retrieve the server's id from a socket
     * @param socket the socket
     */
    private void getServerId(Socket socket) {
        if( (serverId != null) || (socket == null) ) {
            return;
        }
        try {
            BufferedReader in = Utils.getASCIIReader(socket.getInputStream());
            PrintWriter out = Utils.getASCIIWriter(socket.getOutputStream());
            out.println("GET / HTTP/1.0");
            if (hostname != null) {
                writer.println("Host: " + hostname);
            }
            out.println();
            out.flush();
            String line;
            line = in.readLine();
            if( (line != null) && ( ! line.startsWith("HTTP/1.")) ) {
                return;
            }
            while( true ) {
                line = in.readLine();
                if( (line == null) || (line.length() == 0) ) {
                    return;
                }
                if( line.toLowerCase().startsWith("server: ") ) {
                    line = line.substring("server: ".length());
                    serverId = line.trim();
                }
            }
        } catch( IOException e ) {
            // ignore
        }
    }

    /**
     * Write a html footer sequence
     */
    private void writeFooter() {
        writer.println("<P>Back to the <A HREF=\"" + backUrl + "\">server selection page</A>.<BR>");
        writer.println("<HR>");        
        writer.println("</BODY></HTML>");
        writer.flush();
    }

    private void writeEM(String message) {
        writer.println("<P><STRONG>" + message + "</STRONG><BR>");
    }

    private void writeLine() {
        writer.println("<BR>");
    }

    private void writeStackTrace(String message, Throwable e) {
        if( message != null ) {
            writer.println(message);
        }
        writer.println("<PRE>");
        e.printStackTrace(writer);
        writer.println("</PRE>");
    }


}
