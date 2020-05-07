package harry.security.responder.resources;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.junit.Test;

import javax.ws.rs.core.Response;
import java.io.InputStream;
import java.net.URL;
import java.util.Base64;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

public class SignerTest {

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
        post.setHeader("signatureType","CMS");
        post.setHeader("mode", "explicit");
        HttpEntity entity = new InputStreamEntity(keyStore);
        post.setEntity(entity);
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
        post.setHeader("signatureType","CAdES");
        post.setHeader("mode", "explicit");
        HttpEntity entity = new InputStreamEntity(keyStore);
        post.setEntity(entity);
        CloseableHttpResponse response = httpClient.execute(post);
        assertThat(response.getEntity().getContent(), notNullValue());
        assertThat(response.getStatusLine().getStatusCode(),
                is(201));
    }

}
