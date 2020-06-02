package org.harry.security.util;

import iaik.security.ssl.*;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Hashtable;

public class ServerInfoGetter {


    private final static int SOCKET_TIMEOUT = 15*1000; // 15 seconds

    public final static int VERSION_SSL20 = SSLContext.VERSION_SSL20;
    public final static int VERSION_SSL30 = SSLContext.VERSION_SSL30;
    public final static int VERSION_TLS10 = SSLContext.VERSION_TLS10;
    public final static int VERSION_TLS11 = SSLContext.VERSION_TLS11;
    public final static int VERSION_TLS12 = SSLContext.VERSION_TLS12;
    public final static int VERSION_TLS13 = SSLContext.VERSION_TLS13;

    public final static int[] VERSIONS = {
            VERSION_SSL30,
            VERSION_TLS10,
            VERSION_TLS11,
            VERSION_TLS12,
            VERSION_TLS13
    };

    private String hostname;
    private int port;


    private InetAddress hostAddress;
    private SSLClientContext context;
    private Throwable exception;
    private Hashtable<java.security.cert.X509Certificate, java.security.cert.X509Certificate[]> serverCerts;
    private boolean eccAvailable;

    public ServerInfoGetter(String hostname, int port) {
        this.hostname = hostname;
        this.port = port;

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

        ServerInfo.init();
        if (hostname.indexOf("<") != -1) {
            // do not echo hostname (XSS)
            hostname = null;
        }



        if (hostname != null) {
            try {
                hostAddress = InetAddress.getByName(hostname);
            } catch( UnknownHostException e ) {
                // do not echo hostname (XSS)
                hostname = null;
            }
        }

        if (hostname == null) {
            return serverCerts;
        }
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


        try {
            socket = new SSLSocket(hostAddress, port, context);
            socket.setSoTimeout(SOCKET_TIMEOUT);
        } catch( IOException e ) {
            IaikSSLUtil.close(socket);
            return serverCerts;
        }

        context.setAllowedProtocolVersions(VERSION_SSL30, VERSION_TLS13);

        boolean ok = tryConnect(socket);

        if( !ok ) {
          return serverCerts;
        }


        if( ServerInfo.okTLS12 == false ) {
            context.setAllowedProtocolVersions(VERSION_TLS12, VERSION_TLS12);
            tryConnect(null);
        }

        if( ServerInfo.okTLS11 == false ) {
            context.setAllowedProtocolVersions(VERSION_TLS11, VERSION_TLS11);
            tryConnect(null);
        }

        if( ServerInfo.okTLS10 == false ) {
            context.setAllowedProtocolVersions(VERSION_TLS10, VERSION_TLS10);
            tryConnect(null);
        }



        if( ServerInfo.okSSL3 == false ) {
            context.setAllowedProtocolVersions(VERSION_SSL30, VERSION_SSL30);
            tryConnect(null);
        }




        if( ServerInfo.okSSL2 == false ) {
            context.setAllowedProtocolVersions(VERSION_SSL20, VERSION_SSL20);
            tryConnect(null);
        }










        if( ServerInfo.okSSL2 ) {
            ServerInfo.v2All = new CipherSuiteList(CipherSuite.CS_SSL_V2);





        }

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
                                if (ServerInfo.okTLS13) version = ver;
                                break;
                            case VERSION_TLS12 :
                                if (ServerInfo.okTLS12) version = ver;
                                break;
                            case VERSION_TLS11 :
                                if (ServerInfo.okTLS11) version = ver;
                                break;
                            case VERSION_TLS10 :
                                if (ServerInfo.okTLS10) version = ver;
                                break;
                            case VERSION_SSL30 :
                                if (ServerInfo.okSSL3) version = ver;
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




        for(Enumeration<java.security.cert.X509Certificate[]> e = serverCerts.elements(); e.hasMoreElements(); ) {
            java.security.cert.X509Certificate[] next = e.nextElement();
            String type = Utils.certTypeToString(Utils.getCertificateType(next));

        }


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
                ServerInfo.okTLS13 = true;
            } else if( version == VERSION_TLS12 ) {
                ServerInfo.okTLS12 = true;
            } else if( version == VERSION_TLS11 ) {
                ServerInfo.okTLS11 = true;
            } else if( version == VERSION_TLS10 ) {
                ServerInfo.okTLS10 = true;
            } else if( version == VERSION_SSL30 ) {
                ServerInfo.okSSL3 = true;
            } else if( version == VERSION_SSL20 ) {
                if( ServerInfo.okSSL2 == false ) {
                    ServerInfo.okSSL2 = true;
                    ServerInfo.v2Suites = socket.getPeerSupportedCipherSuiteList();
                    ServerInfo.v2Cert = socket.getPeerCertificateChain()[0];
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
        if( (ServerInfo.serverId != null) || (socket == null) ) {
            return;
        }
        try {
            BufferedReader in = Utils.getASCIIReader(socket.getInputStream());
            PrintWriter out = Utils.getASCIIWriter(socket.getOutputStream());
            out.println("GET / HTTP/1.0");

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
                    ServerInfo.serverId = line.trim();
                }
            }
        } catch( IOException e ) {
            // ignore
        }
    }









    public static class ServerInfo {
        public static boolean okSSL2, okSSL3, okTLS10, okTLS11, okTLS12, okTLS13;
        public static String serverId;
        public static CipherSuiteList v2All;
        public static CipherSuiteList notSupportedCipherSuites;
        public static CipherSuiteList v2Suites;
        public static java.security.cert.X509Certificate v2Cert;
        public static void init() {
            boolean okSSL2, okSSL3, okTLS10, okTLS11, okTLS12, okTLS13 = false;
            String serverId = null;
            CipherSuiteList v2All = null;
            CipherSuiteList notSupportedCipherSuites = null;
            CipherSuiteList v2Suites = null;
            java.security.cert.X509Certificate v2Cert = null;
        }
    }


}
