package org.harry.security.util;

import iaik.security.ssl.*;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import org.pmw.tinylog.Logger;

import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Hashtable;

import static iaik.security.ssl.CertificateStatusRequest.STATUS_TYPE_OCSP;

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
    private Hashtable<X509Certificate, X509Certificate[]> serverCerts;
    private boolean eccAvailable;
    TLS13OCSPCertStatusChainVerifier chainVerifier;
    byte [] statusReqEncoded = null;

    public ServerInfoGetter(String hostname, int port) {
        this.hostname = hostname;
        this.port = port;

        context = new SSLClientContext();
        context.setSessionManager(null);
        chainVerifier =  new TLS13OCSPCertStatusChainVerifier();;
        // set OCSPCertStatusChainVerifier
        context.setChainVerifier(chainVerifier);// no session caching
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
        serverCerts = new Hashtable<X509Certificate, X509Certificate[]>();
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

    private void setExtensionsWithStatus(SSLContext context) throws IOException {

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
        OCSPStatusRequest statusRequest = new OCSPStatusRequest();
        CertificateStatusRequest request = new CertificateStatusRequest(OCSPStatusRequest.STATUS_TYPE, statusRequest.getEncoded());
        statusReqEncoded = request.getStatusRequest();
        extensions.addExtension(request);
        context.setExtensions(extensions);

    }


    /**
     * Get the SSL information of a given host
     * @return the SSL certificates HashTable
     */
    public Hashtable<X509Certificate, X509Certificate[]> getInformation() throws IOException {

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

                context.setEnabledCipherSuites(new CipherSuite[] { suite });
                setExtensions(context);
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




        for(Enumeration<X509Certificate[]> e = serverCerts.elements(); e.hasMoreElements(); ) {
            X509Certificate[] next = e.nextElement();
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
        serverCerts.put(certIAIK[0], certIAIK);
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
    /**
     * Creates a SSLSocket for connecting to the given server.
     *
     * @param serverName the server name
     * @param serverPort the port the server is listening for connections
     * @param context the SSLContext with the TLS client configuration
     *
     * @exception IOException if an error occurs when connecting to the server
     */
    public CertStatusValue ocspCheckStapling(String serverName, int serverPort,
                                     SSLClientContext context) throws IOException  {

        boolean verifyOK = false;
        SSLSocket socket = null;
        try {

            // connect
            System.out.println("Connect to " + serverName + " on port " + serverPort);
            socket = new SSLSocket(serverName, serverPort, context);
            // print debug info to System.out
            socket.setDebugStream(System.out);
            // start handshake
            socket.startHandshake();
            System.out.println();

            // informations about the server:
            System.out.println("TLS-Connection established. Session-Parameter:");
            System.out.println("Active cipher suite: " + socket.getActiveCipherSuite());
            System.out.println("Active compression method: " + socket.getActiveCompressionMethod());
            java.security.cert.X509Certificate[] chain = socket.getPeerCertificateChain();
            if (chain != null) {
                System.out.println("Server certificate chain:");
                for (int i=0; i<chain.length; i++) {
                    System.out.println("Certificate " + i + ": " +
                            chain[i].getSubjectDN());
                }
            }
            System.out.println();

            ExtensionList peerExtensions = socket.getPeerExtensions();
            ExtensionList activeExtensions = socket.getActiveExtensions();

            System.out.println("Extensions sent by the server: " + ((peerExtensions == null) ? "none" : peerExtensions.toString()));

            TLS13Certificate.CertificateEntry[] tls13Certificates = new TLS13Certificate.CertificateEntry[chain.length];
            int index = 0;
            for (; index < tls13Certificates.length; index++) {
                tls13Certificates[index] = new TLS13Certificate.X509CertificateEntry(chain[index]);
            }
            verifyOK = chainVerifier.verifyChain( tls13Certificates,
                    socket.getTransport(), STATUS_TYPE_OCSP, statusReqEncoded);

            System.out.println("Chain verificationended with : " + Boolean.valueOf(verifyOK).toString());
            index = 0;
            for (; index < tls13Certificates.length; index++) {
                ExtensionList certExtensions = tls13Certificates[index].getExtensions();
                if (certExtensions != null) {
                    certExtensions.toString(true);
                }
            }

            if (verifyOK) {
                return CertStatusValue.STATUS_OK;
            } else {
                return CertStatusValue.STATUS_NOK;
            }
        } catch( IOException ex) {
            Logger.trace("IOException:" + ex.getMessage());
            return CertStatusValue.STATUS_CHECK_GO_ON;
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
    }

    public SSLClientContext freshContext() throws IOException{
        SSLClientContext clientContext = new SSLClientContext();
        clientContext.setSessionManager(null);
        chainVerifier = new TLS13OCSPCertStatusChainVerifier();
        // set OCSPCertStatusChainVerifier
        clientContext.setChainVerifier(chainVerifier);// no session caching
        // allow legacy renegotiation
        clientContext.setAllowLegacyRenegotiation(true);
        // ECC available?
        setExtensionsWithStatus(clientContext);
        return clientContext;
    }

    public static enum CertStatusValue {
        STATUS_OK,
        STATUS_CHECK_GO_ON,
        STATUS_NOK
    }

}
