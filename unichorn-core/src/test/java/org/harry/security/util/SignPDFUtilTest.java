package org.harry.security.util;

import com.google.gson.Gson;
import iaik.cms.SecurityProvider;
import iaik.cms.ecc.ECCelerateProvider;
import iaik.pdf.parameters.PadesBESParameters;
import iaik.security.ec.provider.ECCelerate;
import iaik.security.provider.IAIKMD;
import iaik.x509.X509Certificate;
import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.InputStreamBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.GSON;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Base64;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

public class SignPDFUtilTest {


    @BeforeClass
    public static void init() {
        IAIKMD.addAsProvider();
        ECCelerate ecc = new ECCelerate();
        Security.insertProviderAt(ecc, 3);
        SecurityProvider.setSecurityProvider(new ECCelerateProvider());
    }

    @Test
    public void signPDFSSimple() throws Exception {
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        SignPDFUtil util = new SignPDFUtil(keys.getFirst(), keys.getSecond());
        InputStream input = SignPDFUtilTest.class.getResourceAsStream("/data/ergo.pdf");
        File out = File.createTempFile("data", ".pdf");
        out.delete();
        SigningBean bean = new SigningBean().setOutputPath(out.getAbsolutePath())
                .setTspURL("http://zeitstempel.dfn.de")
                .setDataIN(input);
        PadesBESParameters params = util.createParameters(bean);
        util.signPDF(bean,  params);
    }

    @Test
    public void signPDFIAIK() throws Exception {
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        SignPDFUtil util = new SignPDFUtil(keys.getFirst(), keys.getSecond());
        InputStream input = SignPDFUtilTest.class.getResourceAsStream("/data/ergo.pdf");
        File out = File.createTempFile("data", ".pdf");
        out.delete();
        SigningBean bean = new SigningBean().setOutputPath(out.getAbsolutePath())
                .setTspURL("http://zeitstempel.dfn.de")
                .setDataIN(input);
        PadesBESParameters params = util.createParameters(bean);
        util.prepareSigning(bean,params);
        util.signPdf();
    }


    @Test
    public void testSignSimplePAdES() throws Exception {
        InputStream input = SignPDFUtilTest.class.getResourceAsStream("/data/ergo.pdf");
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
        param.signing.signatureType = "PAdES";
        param.signing.cadesParams =  new GSON.SigningCAdES();
        param.signing.cadesParams.TSAURL = "http://zeitstempel.dfn.de";
        Gson gson = new Gson();
        String jsonString = gson.toJson(param);
        StringBody json = new StringBody(jsonString, ContentType.APPLICATION_JSON);
        InputStreamBody inputBody = new InputStreamBody(input, ContentType.APPLICATION_OCTET_STREAM);
        System.err.println(param.toString());
        MultipartEntityBuilder builder =MultipartEntityBuilder.create()
                .addPart("params",
                        json)
                .addPart("data_to_sign", inputBody);

        post.setEntity(builder.build());
        CloseableHttpResponse response = httpClient.execute(post);
        assertThat(response.getEntity().getContent(), notNullValue());
        File temp = File.createTempFile("data", ".pdf");
        IOUtils.copy(response.getEntity().getContent(), new FileOutputStream(temp));
        assertThat(response.getStatusLine().getStatusCode(),
                is(201));
    }

}
