package org.harry.security.util.httpclient;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import javax.xml.ws.Response;
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.util.Base64;
import java.util.Vector;

public class HttpClientConnection {

    public static InputStream sendGetForResources(URL connectUrl,
                                                            String fileType, OutputStream output) {
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            System.out.println("Responder URL: " + connectUrl.toString());
            HttpGet get = new HttpGet(connectUrl.toURI());
            get.setHeader("fileType", fileType);
            CloseableHttpResponse response = httpClient.execute(get);
            if (response.getStatusLine().getStatusCode() == 200) {
                InputStream result = response.getEntity().getContent();
                byte [] content = IOUtils.toByteArray(result);
                ByteArrayInputStream input = new ByteArrayInputStream(content);
                IOUtils.copy(input, output);
                input = new ByteArrayInputStream(content);
                result.close();
                output.close();
                return input;
            }
            return null;
        } catch (Exception ex) {
            throw new IllegalStateException("error getting resource", ex);
        }
    }

    public static void sendPutData(InputStream data, String fileType) throws Exception {
        URL ocspUrl= new URL("http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/ocsp");
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = HttpClients.createDefault();
        System.out.println("Responder URL: " + ocspUrl.toString());
        HttpPut put = new HttpPut(ocspUrl.toURI());
        put.setHeader("fileType", fileType);
        byte [] encoded = Base64.getEncoder().encode("geheim".getBytes());
        String encodeString = new String(encoded);
        put.setHeader("passwd",encodeString);
        put.setHeader("storeType", "PKCS12");
        HttpEntity entity = new InputStreamEntity(data);
        put.setEntity(entity);
        CloseableHttpResponse response = httpClient.execute(put);
    }


    public static void sendPutDataWithPath(InputStream data, String fileType, Vector<String> path) throws Exception {
        URL ocspUrl= new URL("http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/ocsp");
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = HttpClients.createDefault();
        System.out.println("Responder URL: " + ocspUrl.toString());
        HttpPut put = new HttpPut(ocspUrl.toURI());
        put.setHeader("fileType", fileType);
        String pathString = path.elementAt(0)+  ";" + path.elementAt(1);
        put.setHeader("path", pathString);
        byte [] encoded = Base64.getEncoder().encode("geheim".getBytes());
        String encodeString = new String(encoded);
        put.setHeader("passwd",encodeString);
        put.setHeader("storeType", "PKCS12");
        HttpEntity entity = new InputStreamEntity(data);
        put.setEntity(entity);
        CloseableHttpResponse response = httpClient.execute(put);
    }
}
