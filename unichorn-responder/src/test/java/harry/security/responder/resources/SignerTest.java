package harry.security.responder.resources;


import com.google.gson.Gson;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.Name;
import iaik.cms.SecurityProvider;
import iaik.cms.ecc.ECCelerateProvider;
import iaik.pkcs.pkcs10.CertificateRequest;
import iaik.pkcs.pkcs8.EncryptedPrivateKeyInfo;
import iaik.pkcs.pkcs9.ChallengePassword;
import iaik.pkcs.pkcs9.ExtensionRequest;
import iaik.security.ec.provider.ECCelerate;
import iaik.security.provider.IAIKMD;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.KeyUsage;
import org.apache.commons.io.IOUtils;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.InputStreamBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.TrustStrategy;
import org.harry.security.util.CertificateWizzard;
import org.harry.security.util.certandkey.GSON;
import org.junit.Before;
import org.junit.Test;
import org.pmw.tinylog.Configurator;
import org.pmw.tinylog.Level;
import org.pmw.tinylog.writers.ConsoleWriter;


import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Locale;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.harry.security.CommonConst.SIGNING_URL;
import static org.harry.security.util.httpclient.ClientFactory.createSSLClient;

public class SignerTest {

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
    public void testSignSimpleCMS() throws Exception {
        InputStream
                keyStore = SignerTest.class.getResourceAsStream("/application.jks");
        URL ocspUrl= new URL(SIGNING_URL);
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = createSSLClient();
        System.out.println("Responder URL: " + ocspUrl.toString());
        HttpPost post = new HttpPost(ocspUrl.toURI());
        byte [] encoded = Base64.getEncoder().encode("geheim".getBytes());
        String encodeString = new String(encoded);
        GSON.Params param = new GSON.Params();
        param.parmType = "docSign";
        param.signing = new GSON.Signing();
        param.signing.mode = 2;
        param.signing.signatureType = "CMS";
        Gson gson = new Gson();
        String jsonString = gson.toJson(param);
        StringBody json = new StringBody(jsonString, ContentType.APPLICATION_JSON);
        InputStreamBody input = new InputStreamBody(keyStore, ContentType.APPLICATION_OCTET_STREAM);
        System.err.println(param.toString());
        MultipartEntityBuilder builder =MultipartEntityBuilder.create()
                .addPart("params",
                        json)
                .addPart("data_to_sign", input);

        post.setEntity(builder.build());
        CloseableHttpResponse response = httpClient.execute(post);
        assertThat(response.getEntity().getContent(), notNullValue());
        assertThat(response.getStatusLine().getStatusCode(),
                is(201));
    }

    @Test
    public void testSignSimpleCAdES() throws Exception {
        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String s, SSLSession sslSession) {
                return true;
            }
        });
        InputStream
                keyStore = SignerTest.class.getResourceAsStream("/application.p12");
        URL ocspUrl= new URL(SIGNING_URL);
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = createSSLClient();
        System.out.println("Responder URL: " + ocspUrl.toString());
        HttpPost post = new HttpPost(ocspUrl.toURI());
        byte [] encoded = Base64.getEncoder().encode("geheim".getBytes());
        String encodeString = new String(encoded);
        GSON.Params param = new GSON.Params();
        param.parmType = "docSign";
        param.signing = new GSON.Signing();
        param.signing.mode = 2;
        param.signing.signatureType = "CAdES";
        Gson gson = new Gson();
        String jsonString = gson.toJson(param);
        StringBody json = new StringBody(jsonString, ContentType.APPLICATION_JSON);
        InputStreamBody input = new InputStreamBody(keyStore, ContentType.APPLICATION_OCTET_STREAM);
        System.err.println(param.toString());
        MultipartEntityBuilder builder =MultipartEntityBuilder.create()
                .addPart("params",
                        json)
        .addPart("data_to_sign", input);

        post.setEntity(builder.build());
        CloseableHttpResponse response = httpClient.execute(post);
        assertThat(response.getEntity().getContent(), notNullValue());
        assertThat(response.getStatusLine().getStatusCode(),
                is(200));
    }

    @Test
    public void testSignSimpleCert() throws Exception {
        String password = getPassCode();
        String token = getToken();

        KeyPair pair = CertificateWizzard.generateKeyPair("RSA", 2048);
        InputStream
                certReqStream = createCertificateRequestStream(pair, password);

        InputStream privKeyEncr = createPrivKeyEncr(pair.getPrivate(), password);

        URL ocspUrl= new URL(SIGNING_URL);
        URIBuilder uriBuilder = new URIBuilder(ocspUrl.toURI());
        uriBuilder.addParameter("token", token);
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = createSSLClient();
        System.out.println("Responder URL: " + ocspUrl.toString());
        HttpPost post = new HttpPost(uriBuilder.build());
        byte [] encoded = Base64.getEncoder().encode("geheim".getBytes());
        String encodeString = new String(encoded);
        GSON.Params param = new GSON.Params();
        param.parmType = "certSign";
        Gson gson = new Gson();
        String jsonString = gson.toJson(param);
        StringBody json = new StringBody(jsonString, ContentType.APPLICATION_JSON);
        InputStreamBody input = new InputStreamBody(certReqStream, ContentType.APPLICATION_OCTET_STREAM);
        InputStreamBody info = new InputStreamBody(privKeyEncr, ContentType.APPLICATION_OCTET_STREAM);
        System.err.println(param.toString());
        MultipartEntityBuilder builder =MultipartEntityBuilder.create()
                .addPart("params",
                        json)
                .addPart("data_to_sign", input)
                .addPart("info", info);

        post.setEntity(builder.build());
        CloseableHttpResponse response = httpClient.execute(post);
        assertThat(response.getEntity().getContent(), notNullValue());
        assertThat(response.getStatusLine().getStatusCode(),
                is(201));
    }

    @Test
    public void checkJson() {
        GSON.Params param = new GSON.Params();
        param.signing = new GSON.Signing();
        param.signing.mode = 2;
        param.signing.signatureType = "CAdES";
        Gson gson = new Gson();
        String json = gson.toJson(param);
        System.out.println(json);
        GSON.Params newObj = gson.fromJson(json, GSON.Params.class);
        assertThat(newObj.signing.signatureType, is(param.signing.signatureType));

    }

    public InputStream createCertificateRequestStream(KeyPair pair, String password) throws Exception {


        // create a new Name
        Name subject = new Name();
        subject.addRDN(ObjectID.country, "AT");
        subject.addRDN(ObjectID.locality, "Graz");
        subject.addRDN(ObjectID.organization, "TU Graz");
        subject.addRDN(ObjectID.organizationalUnit, "IAIK");
        subject.addRDN(ObjectID.commonName, "PKCS#10 Test");
        // new CertificateRequest
        CertificateRequest request = new CertificateRequest(pair.getPublic(),
                subject);
        // and define some attributes
        Attribute[] attributes = new Attribute[2];
        // add a ExtensionRequest attribute for KeyUsage digitalSignature and nonRepudiation
        KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature
                | KeyUsage.nonRepudiation);
        ExtensionRequest extensionRequest = new ExtensionRequest();
        extensionRequest.addExtension(keyUsage);
        attributes[0] = new Attribute(extensionRequest);
        // and an challenge password
        ChallengePassword challengePassword = new ChallengePassword(password);
        attributes[1] = new Attribute(challengePassword);
        // now set the attributes
        request.setAttributes(attributes);
        // sign the request
        request.sign(AlgorithmID.sha3_256WithRSAEncryption, pair.getPrivate());
        System.out.println("Request generated:");
        System.out.println(request);
        System.out.println();
        // write the DER encoded Request to an OutputStream
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        request.writeTo(os);
        ByteArrayInputStream input = new ByteArrayInputStream(os.toByteArray());
        return input;
    }

    private InputStream createPrivKeyEncr(PrivateKey privateKey, String password) throws NoSuchAlgorithmException {
        // wrap, encrypt, encode
        EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(
                privateKey);
        epki.encrypt(password.toCharArray(), "PbeWithSHAAnd3_KeyTripleDES_CBC");
        byte[] encodedEpki = epki.getEncoded();
        ByteArrayInputStream result = new ByteArrayInputStream(encodedEpki);
        return result;
    }

    private String getPassCode() throws Exception {
        URL ocspUrl= new URL(SIGNING_URL);
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = createSSLClient();
        URIBuilder builder = new URIBuilder(ocspUrl.toURI());
        builder.addParameter("action", "passwd");
        System.out.println("Responder URL: " + builder.build().toString());
        HttpGet get = new HttpGet(builder.build());
        CloseableHttpResponse response = httpClient.execute(get);
        InputStream result = response.getEntity().getContent();
        String text = IOUtils.toString(result, StandardCharsets.UTF_8.name());
        return text;
    }

    private String getToken() throws Exception {
        URL ocspUrl= new URL(SIGNING_URL);
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = createSSLClient();
        URIBuilder builder = new URIBuilder(ocspUrl.toURI());
        builder.addParameter("action", "token");
        System.out.println("Responder URL: " + builder.build().toString());
        HttpGet get = new HttpGet(builder.build());
        byte [] encoded = Base64.getEncoder().encode("geheim".getBytes());
        String encodeString = new String(encoded);
        get.setHeader("passwd", encodeString);
        CloseableHttpResponse response = httpClient.execute(get);
        InputStream result = response.getEntity().getContent();
        String text = IOUtils.toString(result, StandardCharsets.UTF_8.name());
        return text;
    }


}
