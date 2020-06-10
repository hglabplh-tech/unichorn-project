package harry.security.responder.resources;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.SecurityProvider;
import iaik.cms.ecc.ECCelerateProvider;
import iaik.security.ec.provider.ECCelerate;
import iaik.security.provider.IAIKMD;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.*;
import iaik.x509.ocsp.net.HttpOCSPRequest;
import iaik.x509.ocsp.utils.ResponseGenerator;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.harry.security.util.*;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.certandkey.CertificateChainUtil;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.ocsp.HttpOCSPClient;
import org.harry.security.util.ocsp.OCSPCRLClient;
import org.harry.security.util.trustlist.TrustListManager;
import org.junit.Before;
import org.junit.Test;
import org.pmw.tinylog.Configurator;
import org.pmw.tinylog.Level;
import org.pmw.tinylog.Logger;
import org.pmw.tinylog.writers.ConsoleWriter;

import javax.ws.rs.core.Response;
import java.io.*;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.util.*;

import static harry.security.responder.resources.UnicHornResponderUtil.*;
import static org.harry.security.CommonConst.APP_DIR_TRUST;
import static org.harry.security.CommonConst.OCSP_URL;
import static org.harry.security.util.HttpsChecker.loadKey;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class ResponderTest  {


    private static final String ALIAS = "Common T-Systems Green TeamUserRSA";

    @Before
    public void init () {
        IAIKMD.addAsProvider();
        ECCelerate ecProvider = ECCelerate.getInstance();
        Security.insertProviderAt(ecProvider, 3);
        SecurityProvider.setSecurityProvider(new ECCelerateProvider());

        Configurator.defaultConfig()
                .writer(new ConsoleWriter())
                .locale(Locale.GERMANY)
                .level(Level.TRACE)
                .activate();
    }

    @Test
    public void nativeCaller() throws Exception {
        List<X509Certificate> certList= new ArrayList<>();
        certList.add(new CertWriterReader().readFromFilePEM(
                ResponderTest.class.getResourceAsStream("/DeutscheTelekomAGIssuingCA01.crt")));
        certList.add(new X509Certificate(ResponderTest.class.getResourceAsStream("/hglabplh.cer")));
        Tuple<PrivateKey, X509Certificate[]> keys = null;

        InputStream
                keyStore = ResponderTest.class.getResourceAsStream("/application.jks");
        KeyStore store = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "PKCS12");
        keys = KeyStoreTool.getKeyEntry(store, ALIAS, "geheim".toCharArray());
        X509Certificate[] certs = new X509Certificate[2];
        certs = keys.getSecond();
                /*OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, bean.getSelectedKey(),
                        certs, certList.toArray(new X509Certificate[0]), false);*/
        int responseStatus = 0;
        for (X509Certificate cert : certList) {
            String ocspUrlOrig = OCSPCRLClient.getOCSPUrl(cert);
            URL ocspUrl= new URL(OCSP_URL);
            /*OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, keys.getFirst(),
                    certs, certList.toArray(new X509Certificate[0]), true); */
            OCSPCRLClient client = new OCSPCRLClient();
            OCSPRequest request = client.createOCSPRequest(null, null,
                    certList.toArray(new X509Certificate[0]),
                    ReqCert.certID, ocspUrlOrig, true);

            ByteArrayInputStream stream = new ByteArrayInputStream(request.getEncoded());
            OCSPResponse response = UnicHornResponderUtil.generateResponse(request,
                    stream);
            client.parseOCSPResponse(response, false);

        }

    }

    @Test
    public void nativeCallerSigningStore() throws Exception {
        InputStream keystoreIN = ResponderTest.class.getResourceAsStream("/signing.p12");
        KeyStore store = KeyStoreTool.loadStore(keystoreIN, "changeit".toCharArray(), "PKCS12");
        Enumeration<String> aliases = store.aliases();
        Tuple<PrivateKey, X509Certificate[]> keys = null;
        if (aliases.hasMoreElements()) {
            keys = KeyStoreTool.getKeyEntry(store, aliases.nextElement(), "changeit".toCharArray());
        }
        String ocspURL = OCSPCRLClient.getOCSPUrl(keys.getSecond()[0]);
        OCSPCRLClient client = new OCSPCRLClient();
        OCSPRequest request = client.createOCSPRequest(null,
                null, keys.getSecond(),
                ReqCert.certID, null, true);

        ByteArrayInputStream stream = new ByteArrayInputStream(request.getEncoded());
        OCSPResponse response = UnicHornResponderUtil.generateResponse(request,
                stream);
        client.parseOCSPResponse(response, false);

    }

    @Test
    public void nativeCallerSigned() throws Exception {
        List<X509Certificate> certList= new ArrayList<>();
        X509Certificate certificate = new X509Certificate(ResponderTest.class.getResourceAsStream("/hglabplh.cer"));
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        X509Certificate [] chain = CertificateChainUtil.resolveTrustedChain(certificate, null, walkers, null);
        for (X509Certificate actual: chain) {
            certList.add(actual);
        }
        Tuple<PrivateKey, X509Certificate[]> keys = null;

        InputStream
                keyStore = ResponderTest.class.getResourceAsStream("/application.p12");
        KeyStore store = KeyStoreTool.loadAppStore();
        keys = KeyStoreTool.getAppKeyEntry(store);
        X509Certificate[] certs = new X509Certificate[2];
        certs = keys.getSecond();
        for (X509Certificate cert : certList) {
            String ocspURL = OCSPCRLClient.getOCSPUrl(certList.get(0));
            OCSPCRLClient client = new OCSPCRLClient();
            OCSPRequest request = client.createOCSPRequest(keys.getFirst(),
                    certs, certList.toArray(new X509Certificate[0]),
                    ReqCert.certID, null, true);

            ByteArrayInputStream stream = new ByteArrayInputStream(request.getEncoded());
            OCSPResponse response = UnicHornResponderUtil.generateResponse(request,
                    stream);
            client.parseOCSPResponse(response, false);

        }

    }

    @Test
    public void nativeCallerSignedQualifiedStore() throws Exception {
        List<X509Certificate []> certList= new ArrayList<>();
        Tuple<PrivateKey, X509Certificate[]> keys = null;

        InputStream
                keyStore = ResponderTest.class.getResourceAsStream("/qualified.p12");
        KeyStore userStore = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "PKCS12");
        Enumeration<String> aliases = userStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Tuple<PrivateKey, X509Certificate[]> userKeys = KeyStoreTool.getKeyEntry(userStore, alias, "geheim".toCharArray());
            certList.add(userKeys.getSecond());
        }
        KeyStore store = KeyStoreTool.loadAppStore();
        keys = KeyStoreTool.getAppKeyEntry(store);
        X509Certificate[] certs = new X509Certificate[2];
        certs = keys.getSecond();
        for (X509Certificate[] certChain : certList) {
            if (certChain.length >= 2) {
                String ocspURL = OCSPCRLClient.getOCSPUrl(certChain[0]);
                OCSPCRLClient client = new OCSPCRLClient();
                OCSPRequest request = client.createOCSPRequest(keys.getFirst(),
                        certs, certChain,
                        ReqCert.certID, null, true);

                ByteArrayInputStream stream = new ByteArrayInputStream(request.getEncoded());
                OCSPResponse response = UnicHornResponderUtil.generateResponse(request,
                        stream);
                client.parseOCSPResponse(response, false);
            }

        }

    }


    @Test
    public void nativeCallerSigned2() throws Exception {
        checkHttpsCertValidity("https://www.digicert.com", true, true);
        List<X509Certificate[]> certList= new ArrayList<>();
        InputStream keystoreUser = ResponderTest.class.getResourceAsStream("/test.p12");
        KeyStore tsystems = KeyStoreTool.loadStore(keystoreUser, "geheim".toCharArray(), "PKCS12");
        Enumeration<String> aliases = tsystems.aliases();
        while (aliases.hasMoreElements())  {
            String alias = aliases.nextElement();
            X509Certificate[] cert = KeyStoreTool.getCertChainEntry(tsystems, alias);
            certList.add(cert);
        }
        Tuple<PrivateKey, X509Certificate[]> keys = null;

        InputStream
                keyStore = ResponderTest.class.getResourceAsStream("/application.p12");
        KeyStore store = KeyStoreTool.loadAppStore();
        keys = KeyStoreTool.getAppKeyEntry(store);
        X509Certificate[] certs = new X509Certificate[2];
        certs = keys.getSecond();
        for (X509Certificate[] certArray : certList) {
            if (certArray.length > 1) {
                String ocspURL = OCSPCRLClient.getOCSPUrl(certArray[0]);
                OCSPCRLClient client = new OCSPCRLClient();
                OCSPRequest request = client.createOCSPRequest(keys.getFirst(),
                        certs, certArray,
                        ReqCert.certID, ocspURL, true);

                ByteArrayInputStream stream = new ByteArrayInputStream(request.getEncoded());
                OCSPResponse response = UnicHornResponderUtil.generateResponse(request,
                        stream);
                client.parseOCSPResponse(response, false);
            }

        }

    }

    @Test
    public void ocspViaGet() throws Exception {
        checkHttpsCertValidity("https://www.digicert.com", true, true);
        List<X509Certificate[]> certList= new ArrayList<>();
        InputStream keystoreUser = ResponderTest.class.getResourceAsStream("/appKeyStore.p12");
        KeyStore tsystems = KeyStoreTool.loadStore(keystoreUser, "geheim".toCharArray(), "PKCS12");
        Enumeration<String> aliases = tsystems.aliases();
        while (aliases.hasMoreElements())  {
            String alias = aliases.nextElement();
            X509Certificate[] cert = KeyStoreTool.getCertChainEntry(tsystems, alias);
            certList.add(cert);
        }
        Tuple<PrivateKey, X509Certificate[]> keys = null;

        InputStream
                keyStore = ResponderTest.class.getResourceAsStream("/application.p12");
        KeyStore store = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "PKCS12");
        keys = KeyStoreTool.getKeyEntry(store, ALIAS, "geheim".toCharArray());
        X509Certificate[] certs = new X509Certificate[2];
        certs = keys.getSecond();
        for (X509Certificate[] certArray : certList) {
            if (certArray.length > 1) {
                String ocspURL = OCSPCRLClient.getOCSPUrl(certArray[0]);
                OCSPCRLClient client = new OCSPCRLClient();
                OCSPRequest ocspRequest = client.createOCSPRequest(keys.getFirst(),
                        certs, certArray,
                        ReqCert.certID, ocspURL, true);

                String uri = OCSP_URL;
                HttpOCSPRequest request = new HttpOCSPRequest
                        (new URL(uri));
                request.sendGETRequest(ocspRequest);
                OCSPResponse response =request.getOCSPResponse();
                client.parseOCSPResponse(response, false);
            }

        }

    }




    @Test
    public void testOCSPOK() throws Exception {
        List<X509Certificate> certList= new ArrayList<>();
        certList.add(new CertWriterReader().readFromFilePEM(
                ResponderTest.class.getResourceAsStream("/DeutscheTelekomAGIssuingCA01.crt")));
        certList.add(new X509Certificate(ResponderTest.class.getResourceAsStream("/hglabplh.cer")));
        Tuple<PrivateKey, X509Certificate[]> keys = null;

            InputStream keyStore = ResponderTest.class.getResourceAsStream("/application.p12");
            KeyStore store = KeyStoreTool.loadAppStore();

            keys = KeyStoreTool.getAppKeyEntry(store);
        X509Certificate[] certs = new X509Certificate[2];
        certs = keys.getSecond();
                /*OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, bean.getSelectedKey(),
                        certs, certList.toArray(new X509Certificate[0]), false);*/
        int responseStatus = 0;
        for (X509Certificate cert : certList) {
            String ocspUrl = OCSPCRLClient.getOCSPUrl(cert);
            ocspUrl= OCSP_URL;
            /*OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, keys.getFirst(),
                    certs, certList.toArray(new X509Certificate[0]), true); */
            OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, null,
                    null, certList.toArray(new X509Certificate[0]),
                    ReqCert.pKCert, false, true);
            responseStatus = HttpOCSPClient.getClient().parseOCSPResponse(response, false);
        }

    }

    @Test
    public void testOCSPOKSigned() throws Exception {
        List<X509Certificate> certList= new ArrayList<>();
        certList.add(new CertWriterReader().readFromFilePEM(
                ResponderTest.class.getResourceAsStream("/DeutscheTelekomAGIssuingCA01.crt")));
        certList.add(new X509Certificate(ResponderTest.class.getResourceAsStream("/hglabplh.cer")));
        Tuple<PrivateKey, X509Certificate[]> keys = null;

        InputStream keyStore = ResponderTest.class.getResourceAsStream("/application.p12");
        KeyStore store = KeyStoreTool.loadAppStore();

        keys = KeyStoreTool.getAppKeyEntry(store);
        X509Certificate[] certs = new X509Certificate[2];
        certs = keys.getSecond();
        int responseStatus = 0;
        for (X509Certificate cert : certList) {
            String ocspUrl = OCSPCRLClient.getOCSPUrl(cert);
            ocspUrl= OCSP_URL;
            OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, keys.getFirst(),
                    certs, certList.toArray(new X509Certificate[0]),
                    ReqCert.pKCert, false, true);
            responseStatus = HttpOCSPClient.getClient().parseOCSPResponse(response, false);
        }

    }

    @Test
    public void testOCSPOKSigned2() throws Exception {
        List<X509Certificate[]> certList= new ArrayList<>();
        InputStream keystoreUser = ResponderTest.class.getResourceAsStream("/appKeyStore.p12");
        KeyStore tsystems = KeyStoreTool.loadStore(keystoreUser, "geheim".toCharArray(), "PKCS12");
        Enumeration<String> aliases = tsystems.aliases();
        while (aliases.hasMoreElements())  {
            String alias = aliases.nextElement();
            X509Certificate[] cert = KeyStoreTool.getCertChainEntry(tsystems, alias);
            certList.add(cert);
        }
        Tuple<PrivateKey, X509Certificate[]> keys = null;

        InputStream
                keyStore = ResponderTest.class.getResourceAsStream("/application.jks");
        KeyStore store = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "PKCS12");
        keys = KeyStoreTool.getKeyEntry(store, ALIAS, "geheim".toCharArray());
        X509Certificate[] certs = new X509Certificate[2];
        certs = keys.getSecond();
        int responseStatus = 0;
        for (X509Certificate[] certArray : certList) {
            if (certArray.length > 1) {
                String ocspUrl =  OCSPCRLClient.getOCSPUrl(certArray[0]);
                ocspUrl = OCSP_URL;
                /*OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, keys.getFirst(),
                        certs, certArray,
                        true, ReqCert.certID);
                        *
                 */
                OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, null,
                        null, certArray,
                        ReqCert.certID, false, true);
                responseStatus = HttpOCSPClient.getClient().parseOCSPResponse(response, false);
            }
        }

    }

    @Test
    public void checkCertNotAvail() throws Exception {
        ConfigReader.MainProperties  properties = ConfigReader.loadStore();
        String idPart = UUID.randomUUID().toString();
        properties = properties.setKeystorePath("./" + idPart + ".p12");
        CertificateWizzard.generateThis(properties);
        File store  = new File("./" + idPart + ".p12").getAbsoluteFile();
        KeyStore keys = KeyStoreTool.loadStore(new FileInputStream(store), "geheim".toCharArray(), "PKCS12");
        X509Certificate[] chain = KeyStoreTool.getCertChainEntry(keys, keys.aliases().nextElement());
        String ocspUrl =  OCSPCRLClient.getOCSPUrl(chain[0]);
        ocspUrl = OCSP_URL;
        OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, null,
                null, chain,
                ReqCert.certID, false, true);
        BasicOCSPResponse basicOCSPResponse = (BasicOCSPResponse)response.getResponse();
        SingleResponse[] resps = basicOCSPResponse.getSingleResponses();
        System.out.println(resps[0].getCertStatus().toString());
        int responseStatus = HttpOCSPClient.getClient().parseOCSPResponse(response, false);
        assertThat(OCSPCRLClient.CertStatusEnum.fromStatus(resps[0].getCertStatus().getCertStatus()),
                is(OCSPCRLClient.CertStatusEnum.UNKNOWN));
        System.out.println("Status: " + responseStatus);

    }

    @Test
    public void checkCertRevoked() throws Exception {

        InputStream store  = ResponderTest.class.getResourceAsStream("/t-systems.p12");
        KeyStore keys = KeyStoreTool.loadStore(store, "geheim".toCharArray(), "PKCS12");
        X509Certificate[] chain = KeyStoreTool.getCertChainEntry(keys, keys.aliases().nextElement());
        String ocspUrl =  OCSPCRLClient.getOCSPUrl(chain[0]);
        ocspUrl = OCSP_URL;
        OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, null,
                null, chain,
                ReqCert.certID, false, true);
        BasicOCSPResponse basicOCSPResponse = (BasicOCSPResponse)response.getResponse();
        SingleResponse[] resps = basicOCSPResponse.getSingleResponses();
        int responseStatus = HttpOCSPClient.getClient().parseOCSPResponse(response, false);
        System.out.println(resps[0].getCertStatus().toString());
        assertThat(OCSPCRLClient.CertStatusEnum.fromStatus(resps[0].getCertStatus().getCertStatus()),
                is(OCSPCRLClient.CertStatusEnum.REVOKED));
        System.out.println("Status: " + responseStatus);

    }

    @Test
    public void checkCertAvail() throws Exception {

        InputStream store  = ResponderTest.class.getResourceAsStream("/test.p12");
        KeyStore keys = KeyStoreTool.loadStore(store, "geheim".toCharArray(), "PKCS12");
        X509Certificate[] chain = KeyStoreTool.getCertChainEntry(keys, keys.aliases().nextElement());
        String ocspUrl =  OCSPCRLClient.getOCSPUrl(chain[0]);
        ocspUrl = OCSP_URL;
        OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, null,
                null, chain,
                ReqCert.certID, false, true);
        BasicOCSPResponse basicOCSPResponse = (BasicOCSPResponse)response.getResponse();
        SingleResponse[] resps = basicOCSPResponse.getSingleResponses();
        int responseStatus = HttpOCSPClient.getClient().parseOCSPResponse(response, false);
        System.out.println(resps[0].getCertStatus().toString());
        assertThat(OCSPCRLClient.CertStatusEnum.fromStatus(resps[0].getCertStatus().getCertStatus()),
                is(OCSPCRLClient.CertStatusEnum.GOOD));
        System.out.println("Status: " + responseStatus);

    }




    @Test
    public void testPutPKCS12Store() throws Exception {
        InputStream keyStore = ResponderTest.class.getResourceAsStream("/appKeyStore.p12");
        URL ocspUrl= new URL(OCSP_URL);
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = HttpClients.createDefault();
        System.out.println("Responder URL: " + ocspUrl.toString());
        HttpPut put = new HttpPut(ocspUrl.toURI());
        byte [] encoded = Base64.getEncoder().encode("geheim".getBytes());
        String encodeString = new String(encoded);
        put.setHeader("passwd",encodeString);
        put.setHeader("storeType", "PKCS12");
        put.setHeader("fileType", "pkcs12");
        HttpEntity entity = new InputStreamEntity(keyStore);
        put.setEntity(entity);
        CloseableHttpResponse response = httpClient.execute(put);
        assertThat(response.getStatusLine().getStatusCode(),
                is(Response.Status.CREATED.getStatusCode()));
    }

    @Test
    public void testPutTrustList() throws Exception {
        InputStream keyStore = ResponderTest.class.getResourceAsStream("/TL-DE.xml");
        URL ocspUrl= new URL(OCSP_URL);
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = HttpClients.createDefault();
        System.out.println("Responder URL: " + ocspUrl.toString());
        HttpPut put = new HttpPut(ocspUrl.toURI());
        byte [] encoded = Base64.getEncoder().encode("geheim".getBytes());
        String encodeString = new String(encoded);
        put.setHeader("passwd",encodeString);
        put.setHeader("storeType", "PKCS12");
        put.setHeader("fileType", "trust");
        HttpEntity entity = new InputStreamEntity(keyStore);
        put.setEntity(entity);
        CloseableHttpResponse response = httpClient.execute(put);
        assertThat(response.getStatusLine().getStatusCode(),
                is(Response.Status.CREATED.getStatusCode()));
    }

    public static Tuple<Integer, List<X509Certificate>> checkHttpsCertValidity(String checkURL,
                                                                               boolean ocspCheck,
                                                                               boolean altResponder
    ) {
        try {
            InputStream
                    keyStore = ResponderTest.class.getResourceAsStream("/application.jks");
            KeyStore store = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "PKCS12");
            Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getKeyEntry(store, ALIAS, "geheim".toCharArray());
            X509Certificate[] certs = new X509Certificate[2];
            certs = keys.getSecond();

            List<X509Certificate> certList = HttpsChecker.getCertFromHttps(checkURL);
            Map<String, X509Certificate> certMap = CertLoader.loadCertificatesFromWIN();
            boolean success = HttpsChecker.checkCertChain(certList, certMap);
            if (success) {
                System.out.println("found certificate in store");
                if (ocspCheck) {

                    Tuple<PrivateKey, X509Certificate[]> bean = loadKey();

                /*OCSPResponse response = HttpOCSPClient.sendOCSPRequest(ocspUrl, bean.getSelectedKey(),
                        certs, certList.toArray(new X509Certificate[0]), false);*/
                    int responseStatus = 0;
                    for (X509Certificate cert : certList) {
                        String ocspUrlOrig = OCSPCRLClient.getOCSPUrl(cert);

                        if (altResponder) {
                            String ocspUrl = OCSP_URL;
                        }
                        OCSPResponse response;
                        OCSPCRLClient client = new OCSPCRLClient();
                        if (true) {
                            OCSPRequest request = client.createOCSPRequest(keys.getFirst(),
                                    certs,
                                    certList.toArray(new X509Certificate[0]),
                                    ReqCert.certID, ocspUrlOrig, true);

                            ByteArrayInputStream stream = new ByteArrayInputStream(request.getEncoded());
                            response = UnicHornResponderUtil.generateResponse(request,
                                    stream);
                        }
                        int oldStatus = responseStatus;
                        responseStatus = client.parseOCSPResponse(response, true);
                        if(oldStatus != OCSPResponse.successful) {
                            responseStatus = oldStatus;
                        }
                    }

                    return  new Tuple<Integer, List<X509Certificate>>(Integer.valueOf(responseStatus), certList);
                } else {
                    return new Tuple<Integer, List<X509Certificate>>(Integer.valueOf(OCSPResponse.successful), certList);
                }


            } else {
                return new Tuple<Integer, List<X509Certificate>>(Integer.valueOf(OCSPResponse.malformedRequest),
                        Collections.EMPTY_LIST);
            }
        } catch (Exception ex) {
            return new Tuple<Integer, List<X509Certificate>>(Integer.valueOf(OCSPResponse.tryLater),
                    Collections.EMPTY_LIST);
        }

    }

    @Test
    public void keyStoreApply() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        InputStream input = ResponderTest.class.getResourceAsStream("/test.p12");
        IOUtils.copy(input, out);
        ByteArrayInputStream p12Stream = new ByteArrayInputStream(out.toByteArray());
        Logger.trace("Before loading keystore");
        String passwd = "geheim";
        KeyStore storeToApply = KeyStoreTool.loadStore(p12Stream,
                passwd.toCharArray(), "PKCS12");
        Logger.trace("Before calling merge");
        File keyFile = new File(APP_DIR_TRUST, "privKeystore" + ".p12");

        applyKeyStore(keyFile, storeToApply, passwd, passwd, "PKCS12");
        assertThat("file does not exist", keyFile.exists(), is(true));
    }

    @Test
    public void keyStorePWDFun() throws Exception {
        encryptPassword("pwdFile", "geheim");
        String password = decryptPassword("pwdFile");
        assertThat("password does not fit", password, is("geheim"));
    }
}
