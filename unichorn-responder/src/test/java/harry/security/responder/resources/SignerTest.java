package harry.security.responder.resources;


import com.google.gson.Gson;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.Name;
import iaik.cms.SecurityProvider;
import iaik.cms.SignedDataStream;
import iaik.cms.ecc.ECCelerateProvider;
import iaik.pkcs.pkcs10.CertificateRequest;
import iaik.pkcs.pkcs8.EncryptedPrivateKeyInfo;
import iaik.pkcs.pkcs9.ChallengePassword;
import iaik.pkcs.pkcs9.ExtensionRequest;
import iaik.security.ec.provider.ECCelerate;
import iaik.security.provider.IAIKMD;
import iaik.security.rsa.RSAPrivateKey;
import iaik.x509.extensions.KeyUsage;
import javassist.bytecode.ByteArray;
import jdk.nashorn.internal.objects.Global;
import jdk.nashorn.internal.parser.JSONParser;
import org.apache.catalina.fileupload.Multipart;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.entity.mime.MultipartEntity;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.ContentBody;
import org.apache.http.entity.mime.content.InputStreamBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.harry.security.util.CertificateWizzard;
import org.json.HTTP;
import org.json.JSONML;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.pmw.tinylog.Configurator;
import org.pmw.tinylog.Level;
import org.pmw.tinylog.writers.ConsoleWriter;


import javax.ws.rs.core.Response;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Base64;
import java.util.Locale;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

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
        URL ocspUrl= new URL("http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/signing");
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = HttpClients.createDefault();
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
        InputStream
                keyStore = SignerTest.class.getResourceAsStream("/application.jks");
        URL ocspUrl= new URL("http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/signing");
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = HttpClients.createDefault();
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
                is(201));
    }

    @Test
    public void testSignSimpleCert() throws Exception {
        String password = getPassCode();
        KeyPair pair = CertificateWizzard.generateKeyPair("RSA", 2048);
        InputStream
                certReqStream = createCertificateRequestStream(pair, password);

        InputStream privKeyEncr = createPrivKeyEncr(pair.getPrivate(), password);

        URL ocspUrl= new URL("http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/signing");
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = HttpClients.createDefault();
        System.out.println("Responder URL: " + ocspUrl.toString());
        HttpPost post = new HttpPost(ocspUrl.toURI());
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
        URL ocspUrl= new URL("http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/signing");
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = HttpClients.createDefault();
        URIBuilder builder = new URIBuilder(ocspUrl.toURI());
        builder.addParameter("action", "passwd");
        System.out.println("Responder URL: " + builder.build().toString());
        HttpGet get = new HttpGet(builder.build());
        CloseableHttpResponse response = httpClient.execute(get);
        InputStream result = response.getEntity().getContent();
        String text = IOUtils.toString(result, StandardCharsets.UTF_8.name());
        return text;
    }


}
