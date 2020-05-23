package org.harry.security.util.certandkey;

import com.google.gson.Gson;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.Name;
import iaik.pkcs.pkcs10.CertificateRequest;
import iaik.pkcs.pkcs8.EncryptedPrivateKeyInfo;
import iaik.pkcs.pkcs9.ChallengePassword;
import iaik.pkcs.pkcs9.ExtensionRequest;
import iaik.x509.extensions.KeyUsage;
import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.FileEntity;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.entity.mime.content.InputStreamBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.harry.security.util.CertificateWizzard;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Base64;

import static org.harry.security.CommonConst.SIGNING_URL;
import static org.harry.security.util.httpclient.ClientFactory.createSSLClient;

public class CSRHandler {
    public static void signCert(Name subject, String path) throws Exception {
        String password = getPassCode();
        String token = getToken();
        KeyPair pair = CertificateWizzard.generateKeyPair("RSA", 2048);
        InputStream
                certReqStream = createCertificateRequestStream(subject, pair, password);

        InputStream privKeyEncr = createPrivKeyEncr(pair.getPrivate(), password);

        URL ocspUrl= new URL(SIGNING_URL);
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = createSSLClient();
        URIBuilder uriBuilder = new URIBuilder(ocspUrl.toURI());
        uriBuilder.addParameter("token", token);
        System.out.println("Responder URL: " + uriBuilder.build());
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
        MultipartEntityBuilder builder = MultipartEntityBuilder.create()
                .addPart("params",
                        json)
                .addPart("data_to_sign", input)
                .addPart("info", info);

        post.setEntity(builder.build());
        CloseableHttpResponse response = httpClient.execute(post);
        File outFile = new File(path);
        System.out.println("Status Code: " + response.getStatusLine().getStatusCode());
        FileOutputStream stream = new FileOutputStream(outFile);
        IOUtils.copy(response.getEntity().getContent(), stream);

    }

    public static void setSigningCert(File keyStore) throws Exception {
        URL ocspUrl= new URL("http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/signing");
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = createSSLClient();
        System.out.println("Responder URL: " + ocspUrl.toString());
        GSON.Params param = new GSON.Params();
        param.parmType = "setSigningStore";
        Gson gson = new Gson();
        HttpPost post = new HttpPost(ocspUrl.toURI());
        String jsonString = gson.toJson(param);
        StringBody json = new StringBody(jsonString, ContentType.APPLICATION_JSON);
        FileBody fileBody = new FileBody(keyStore);

        MultipartEntityBuilder builder = MultipartEntityBuilder.create()
                .addPart("params",
                        json)
                .addPart("data_to_sign", fileBody);

        System.err.println(param.toString());
        post.setEntity(builder.build());
        CloseableHttpResponse response = httpClient.execute(post);
    }

    public static void setAppProperties(File propFile) throws Exception {
        URL ocspUrl= new URL("http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/signing");
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = createSSLClient();
        System.out.println("Responder URL: " + ocspUrl.toString());
        GSON.Params param = new GSON.Params();
        param.parmType = "saveProps";
        Gson gson = new Gson();
        HttpPost post = new HttpPost(ocspUrl.toURI());
        String jsonString = gson.toJson(param);
        StringBody json = new StringBody(jsonString, ContentType.APPLICATION_JSON);
        FileBody fileBody = new FileBody(propFile);

        MultipartEntityBuilder builder = MultipartEntityBuilder.create()
                .addPart("params",
                        json)
                .addPart("data_to_sign", fileBody);

        System.err.println(param.toString());
        post.setEntity(builder.build());
        CloseableHttpResponse response = httpClient.execute(post);
    }

    public static void initAppKeystore() throws Exception {
        URL ocspUrl= new URL("http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/signing");
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = createSSLClient();
        System.out.println("Responder URL: " + ocspUrl.toString());
        GSON.Params param = new GSON.Params();
        param.parmType = "initKeys";
        Gson gson = new Gson();
        HttpPost post = new HttpPost(ocspUrl.toURI());
        String jsonString = gson.toJson(param);
        StringBody json = new StringBody(jsonString, ContentType.APPLICATION_JSON);


        MultipartEntityBuilder builder = MultipartEntityBuilder.create()
                .addPart("params",
                        json);
        System.err.println(param.toString());
        post.setEntity(builder.build());
        CloseableHttpResponse response = httpClient.execute(post);
    }

    public static void resignCRL() throws Exception {
        URL ocspUrl= new URL("http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/signing");
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = createSSLClient();
        System.out.println("Responder URL: " + ocspUrl.toString());
        GSON.Params param = new GSON.Params();
        param.parmType = "resignCRL";
        Gson gson = new Gson();
        HttpPost post = new HttpPost(ocspUrl.toURI());
        String jsonString = gson.toJson(param);
        StringBody json = new StringBody(jsonString, ContentType.APPLICATION_JSON);


        MultipartEntityBuilder builder = MultipartEntityBuilder.create()
                .addPart("params",
                        json);
        System.err.println(param.toString());
        post.setEntity(builder.build());
        CloseableHttpResponse response = httpClient.execute(post);
    }



    public static InputStream createCertificateRequestStream(Name subject, KeyPair pair, String password) throws Exception {



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

    public static InputStream createPrivKeyEncr(PrivateKey privateKey, String password) throws NoSuchAlgorithmException {
        // wrap, encrypt, encode
        EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(
                privateKey);
        epki.encrypt(password.toCharArray(), "PbeWithSHAAnd3_KeyTripleDES_CBC");
        byte[] encodedEpki = epki.getEncoded();
        ByteArrayInputStream result = new ByteArrayInputStream(encodedEpki);
        return result;
    }

    public static String getPassCode() throws Exception {
        URL ocspUrl= new URL("http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/signing");
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

    public static String getToken() throws Exception {
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
