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
import iaik.x509.X509Certificate;
import iaik.x509.extensions.ExtendedKeyUsage;
import iaik.x509.extensions.KeyUsage;
import iaik.x509.extensions.SubjectKeyIdentifier;
import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.entity.mime.content.InputStreamBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.harry.security.util.CertificateWizzard;
import org.harry.security.util.Tuple;
import org.pmw.tinylog.Logger;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.Enumeration;

import static org.harry.security.CommonConst.*;
import static org.harry.security.util.CertificateWizzard.addQualifiedExtension;
import static org.harry.security.util.httpclient.ClientFactory.createSSLClient;

/**
 * Class for handling servlet requests and CSR Requests
 */
public class CSRHandler {

    /**
     * Sign the certificate with the CSR remote
     * @param subject the subject Name
     * @param path the output path
     * @param keyUsage the key-usage
     * @param ocspSigning flag for ocsp-signing
     * @throws Exception error case
     */
    public static void signCert(Name subject, String path, KeyUsage keyUsage, boolean ocspSigning) throws Exception {
        String password = getPassCode();
        String token = getToken();
        KeyPair pair = CertificateWizzard.generateKeyPair("RSA", 2048);
        InputStream
                certReqStream = createCertificateRequestStream(subject, pair, password, keyUsage, ocspSigning);

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

    /**
     * Sets the keystore as signing key-store for remote signing
     * @param keyStore the keystore
     * @throws Exception error case
     */
    public static void setSigningCert(File keyStore) throws Exception {
        String token = getTokenAdmin();
        URL ocspUrl= new URL(ADMIN_URL);
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = createSSLClient();
        URIBuilder uriBuilder = new URIBuilder(ocspUrl.toURI());
        uriBuilder.addParameter("token", token);
        System.out.println("Responder URL: " + uriBuilder.build());
        HttpPost post = new HttpPost(uriBuilder.build());
        GSON.Params param = new GSON.Params();
        param.parmType = "setSigningStore";
        Gson gson = new Gson();
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

    /**
     * set the application properties
     * @param propFile the properties-file
     * @throws Exception error case
     */
    public static void setAppProperties(File propFile) throws Exception {
        String token = getTokenAdmin();
        URL ocspUrl= new URL(ADMIN_URL);
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = createSSLClient();
        URIBuilder uriBuilder = new URIBuilder(ocspUrl.toURI());
        uriBuilder.addParameter("token", token);
        System.out.println("Responder URL: " + uriBuilder.build());
        HttpPost post = new HttpPost(uriBuilder.build());
        GSON.Params param = new GSON.Params();
        param.parmType = "saveProps";
        Gson gson = new Gson();
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

    /**
     * Initialize the application key-store and trust-list on server side
     * @throws Exception error case
     */
    public static void initAppKeystore(File keyStore, File trustList) throws Exception {
        String token = getTokenAdmin();
        URL ocspUrl= new URL(ADMIN_URL);
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = createSSLClient();
        URIBuilder uriBuilder = new URIBuilder(ocspUrl.toURI());
        uriBuilder.addParameter("token", token);
        System.out.println("Responder URL: " + uriBuilder.build());
        HttpPost post = new HttpPost(uriBuilder.build());
        GSON.Params param = new GSON.Params();
        param.parmType = "copyKeyTrust";
        Gson gson = new Gson();
        String jsonString = gson.toJson(param);
        StringBody json = new StringBody(jsonString, ContentType.APPLICATION_JSON);
        FileBody keystoreBody = new FileBody(keyStore);
        FileBody trustListBody = new FileBody(trustList);

        MultipartEntityBuilder builder = MultipartEntityBuilder.create()
                .addPart("params",
                        json)
                .addPart("keystore",  keystoreBody)
                .addPart("trustlist",  trustListBody);
        System.err.println(param.toString());
        post.setEntity(builder.build());
        CloseableHttpResponse response = httpClient.execute(post);
    }

    /**
     * sign the Certificate revocation list
     * @throws Exception error case
     */
    public static void resignCRL() throws Exception {
        String token = getTokenAdmin();
        URL ocspUrl= new URL(ADMIN_URL);
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = createSSLClient();
        URIBuilder uriBuilder = new URIBuilder(ocspUrl.toURI());
        uriBuilder.addParameter("token", token);
        System.out.println("Responder URL: " + uriBuilder.build());
        HttpPost post = new HttpPost(uriBuilder.build());
        GSON.Params param = new GSON.Params();
        param.parmType = "resignCRL";
        Gson gson = new Gson();
        String jsonString = gson.toJson(param);
        StringBody json = new StringBody(jsonString, ContentType.APPLICATION_JSON);


        MultipartEntityBuilder builder = MultipartEntityBuilder.create()
                .addPart("params",
                        json);
        System.err.println(param.toString());
        post.setEntity(builder.build());
        CloseableHttpResponse response = httpClient.execute(post);
    }

    /**
     * cleanup of the prepared responses to get dynamic responses again from responder
     * @throws Exception error case
     */
    public static void cleanupPreparedResp() throws Exception {
        String token = getTokenAdmin();
        URL ocspUrl= new URL(ADMIN_URL);
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = createSSLClient();
        URIBuilder uriBuilder = new URIBuilder(ocspUrl.toURI());
        uriBuilder.addParameter("token", token);
        System.out.println("Responder URL: " + uriBuilder.build());
        HttpPost post = new HttpPost(uriBuilder.build());
        GSON.Params param = new GSON.Params();
        param.parmType = "cleanupPreparedResp";
        Gson gson = new Gson();
        String jsonString = gson.toJson(param);
        StringBody json = new StringBody(jsonString, ContentType.APPLICATION_JSON);


        MultipartEntityBuilder builder = MultipartEntityBuilder.create()
                .addPart("params",
                        json);
        System.err.println(jsonString);
        post.setEntity(builder.build());
        CloseableHttpResponse response = httpClient.execute(post);
    }


    /**
     * create a CSR
     * @param subject the subject for the new certificate
     * @param pair key-pair of the new certificate
     * @param password the challenge password
     * @param keyUsage the key-usage
     * @param ocspSigning the ocsp-signing usage indicator
     * @return the InputStream containing the request
     * @throws Exception error case
     */
    public static InputStream createCertificateRequestStream(Name subject, KeyPair pair,
                                                             String password, KeyUsage keyUsage,
                                                             boolean ocspSigning) throws Exception {



        // new CertificateRequest
        CertificateRequest request = new CertificateRequest(pair.getPublic(),
                subject);
        // and define some attributes
        Attribute[] attributes = new Attribute[2];

        ExtensionRequest extensionRequest = new ExtensionRequest();
        extensionRequest.addExtension(keyUsage);
        extensionRequest.addExtension(addQualifiedExtension());
        if (ocspSigning) {
            ExtendedKeyUsage extKeyUsage = new ExtendedKeyUsage();
            extKeyUsage.addKeyPurposeID(ExtendedKeyUsage.ocspSigning);
            extKeyUsage.addKeyPurposeID(ExtendedKeyUsage.timeStamping);
            extensionRequest.addExtension(extKeyUsage);
        }
        extensionRequest.addExtension(CertificateWizzard.createOCSPUrl(null, OCSP_URL));


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

    /**
     * encrypt a private key for sending it to peer
     * @param privateKey the private key to encrypt
     * @param password the password
     * @return the encrypted key
     * @throws NoSuchAlgorithmException error case
     */
    public static InputStream createPrivKeyEncr(PrivateKey privateKey, String password) throws NoSuchAlgorithmException {
        // wrap, encrypt, encode
        EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(
                privateKey);
        epki.encrypt(password.toCharArray(), "PbeWithSHAAnd3_KeyTripleDES_CBC");
        byte[] encodedEpki = epki.getEncoded();
        ByteArrayInputStream result = new ByteArrayInputStream(encodedEpki);
        return result;
    }

    /**
     * get the passcode for a new request
     * @return the new passcode
     * @throws Exception error case
     */
    public static String getPassCode() throws Exception {
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

    /**
     * get a new security token
     * @return the fresh token
     * @throws Exception error case
     */
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

    /**
     * get security token for admin-service
     * @return the fresh token
     * @throws Exception error case
     */
    public static String getTokenAdmin() throws Exception {
        URL ocspUrl= new URL(ADMIN_URL);
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

    /**
     * execute the certificate signing request
     * @param certReq the request
     * @param userKey the user-private key
     * @return the private key and the fresh new chain
     */
    public static Tuple<PrivateKey , X509Certificate[]> certSigning(CertificateRequest certReq, PrivateKey userKey)  {
       try {

           PublicKey pubKey = certReq.getPublicKey();
           Name subject = certReq.getSubject();
           KeyStore store = KeyStoreTool.loadAppStore();
           Enumeration<String> aliases = store.aliases();
           Tuple<PrivateKey, X509Certificate[]> keys = null;
           while(aliases.hasMoreElements()) {
               String alias = aliases.nextElement();
               if (alias.contains("Intermediate")) {
                   keys =
                           KeyStoreTool.getKeyEntry(store,alias, "geheim".toCharArray());
                   Logger.trace("Keys found for alias: " + alias);
               }
           }
           if (keys != null) {
               // look for a ChallengePassword attribute
               ChallengePassword challengePassword = (ChallengePassword) certReq
                       .getAttributeValue(ChallengePassword.oid);
               if (challengePassword != null) {
                   System.out.println("Certificate request contains a challenge password: \""
                           + challengePassword.getPassword() + "\".");
               }
               X509Certificate userCert = null;
               Logger.trace("Check challenge password: " + challengePassword.getPassword());
               File pwdFile = new File(APP_DIR_WORKING, challengePassword.getPassword());
               if (!pwdFile.exists()) {
                   Logger.trace("Check challenge password failed");
                   return null;
               } else {
                   pwdFile.delete();
               }
               Logger.trace("Create certificate");
               Name issuer = (Name)keys.getSecond()[0].getSubjectDN();
               ExtensionRequest extensionRequest = (ExtensionRequest) certReq
                       .getAttributeValue(ExtensionRequest.oid);
               if (extensionRequest != null) {
                   // we know that KeyUsage is included
                   KeyUsage keyUsage = (KeyUsage) extensionRequest.getExtension(KeyUsage.oid);
                   SubjectKeyIdentifier subjectKeyID = new SubjectKeyIdentifier(keys.getSecond()[0].getPublicKey());
                   userCert = CertificateWizzard.createCertificate(subject,
                           pubKey, issuer,
                           keys.getFirst(),
                           certReq.getSignatureAlgorithmID(),
                           subjectKeyID.get(),
                           keyUsage);
                   Logger.trace("Create certificate success");
               }
               if (userKey != null && userCert != null) {
                   Logger.trace("Add key to trusted");
                   X509Certificate[] chain = new X509Certificate[3];
                   chain[2] = keys.getSecond()[1];
                   chain[1] = keys.getSecond()[0];
                   chain[0] = userCert;
                   return new Tuple<PrivateKey, X509Certificate[]>(userKey,chain);
               }
           }
       } catch (Exception ex) {
           Logger.trace("error during certificate signing");
           Logger.trace(ex);
           throw new IllegalStateException(
                   "error during certificate signing", ex);
       }
       return null;
    }
}
