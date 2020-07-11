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
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.InputStreamBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.harry.security.testutils.TestBase;
import org.harry.security.util.algoritms.DigestAlg;
import org.harry.security.util.algoritms.SignatureAlg;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.GSON;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.trustlist.TrustListManager;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.activation.DataSource;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.harry.security.CommonConst.SIGNING_URL;
import static org.harry.security.util.certandkey.CSRHandler.getToken;
import static org.harry.security.util.httpclient.ClientFactory.createSSLClient;

public class SignPDFUtilTest extends TestBase {

    @Test
    public void signPDFSSimple() throws Exception {
        InputStream keystoreIN = SigningUtilTest.class.getResourceAsStream("/certificates/signing.p12");
        KeyStore store = KeyStoreTool.loadStore(keystoreIN, "changeit".toCharArray(), "UnicP12");
        Enumeration<String> aliases = store.aliases();
        Tuple<PrivateKey, X509Certificate[]> keys = null;
        if (aliases.hasMoreElements()) {
            keys = KeyStoreTool.getKeyEntry(store, aliases.nextElement(), "changeit".toCharArray());
        }
        assertThat(keys, notNullValue());
        SignPDFUtil util = new SignPDFUtil(keys.getFirst(), keys.getSecond());
        InputStream input = SignPDFUtilTest.class.getResourceAsStream("/data/no-signatures.pdf");
        File out = File.createTempFile("data", ".pdf");
        out.delete();
        SigningBean bean = new SigningBean().setOutputPath(out.getAbsolutePath())
                .setTspURL("http://zeitstempel.dfn.de")
                .setDataIN(input);
        PadesBESParameters params = util.createParameters(bean);
        DataSource ds = util.signPDF(bean, params, "IAIK");
        SigningUtil writer = new SigningUtil();
        writer.writeToFile(ds, bean);

        FileInputStream fin = new FileInputStream(out);
        bean = bean.setDataIN(fin);
        DataSource certified = util.certifyPDF(bean, params, "IAIK");
        writer.writeToFile(certified, bean);

        fin = new FileInputStream(out);
        bean = bean.setDataIN(fin);
        DataSource timestamped = util.timeStampPDF(bean, params);
        writer.writeToFile(timestamped, bean);


        fin = new FileInputStream(out);
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        bean = bean.setCheckPathOcsp(true);
        VerifyPDFUtil vutil = new VerifyPDFUtil(walkers, bean);
        vutil.verifySignedPdf(fin);
    }




    @Test
    public void testSignSimplePAdES() throws Exception {
        InputStream input = SignPDFUtilTest.class.getResourceAsStream("/data/ergo.pdf");
        String token = getToken();
        URL ocspUrl= new URL(SIGNING_URL);
        URIBuilder uriBuilder = new URIBuilder(ocspUrl.toURI());
        uriBuilder.addParameter("token", token);
        System.out.println("Responder URL: " + uriBuilder.build());
        CloseableHttpClient httpClient = createSSLClient();
        HttpPost post = new HttpPost(uriBuilder.build());
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
