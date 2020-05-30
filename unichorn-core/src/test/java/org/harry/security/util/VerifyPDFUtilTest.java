package org.harry.security.util;

import com.google.gson.Gson;
import iaik.pdf.parameters.PadesBESParameters;
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
import org.harry.security.testutils.TestBase;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.GSON;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.trustlist.TrustListManager;
import org.junit.Test;

import javax.activation.DataSource;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.harry.security.CommonConst.SIGNING_URL;
import static org.harry.security.util.certandkey.CSRHandler.getToken;
import static org.harry.security.util.httpclient.ClientFactory.createSSLClient;

public class VerifyPDFUtilTest extends TestBase {

    @Test
    public void verifyPDFSSimple() throws Exception {
        InputStream input = VerifyPDFUtilTest.class.getResourceAsStream("/data/simpleCertifiedSigned.pdf");
        SigningBean bean = new SigningBean()
                .setTspURL("http://zeitstempel.dfn.de")
                .setCheckPathOcsp(true)
                .setDataIN(input);
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        VerifyPDFUtil vutil = new VerifyPDFUtil(walkers, bean);

        vutil.verifySignedPdf(input);
    }






}
