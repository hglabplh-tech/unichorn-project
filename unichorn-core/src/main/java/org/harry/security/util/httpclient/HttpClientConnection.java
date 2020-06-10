package org.harry.security.util.httpclient;

import com.google.gson.Gson;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.InputStreamBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.harry.security.util.certandkey.GSON;

import java.io.*;
import java.net.URL;
import java.util.Base64;
import java.util.Vector;

import static org.harry.security.CommonConst.OCSP_URL;
import static org.harry.security.CommonConst.SIGNING_URL;
import static org.harry.security.util.certandkey.CSRHandler.getToken;
import static org.harry.security.util.httpclient.ClientFactory.createSSLClient;

public class HttpClientConnection {

    public static InputStream sendGetForResources(URL connectUrl,
                                                            String fileType, OutputStream output) {
        try {
            CloseableHttpClient httpClient = createSSLClient();
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

    public static void sendPutData(InputStream data, String fileType, String userPWD) throws Exception {
        URL ocspUrl= new URL(OCSP_URL);
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = createSSLClient();
        System.out.println("Responder URL: " + ocspUrl.toString());
        HttpPut put = new HttpPut(ocspUrl.toURI());
        put.setHeader("fileType", fileType);
        byte [] encoded = Base64.getEncoder().encode("geheim".getBytes());
        String encodeString = new String(encoded);
        put.setHeader("passwd",encodeString);
        encoded = Base64.getEncoder().encode(userPWD.getBytes());
        encodeString = new String(encoded);
        put.setHeader("passwdUser",encodeString);
        put.setHeader("storeType", "PKCS12");
        HttpEntity entity = new InputStreamEntity(data);
        put.setEntity(entity);
        CloseableHttpResponse response = httpClient.execute(put);
    }


    public static void sendPutDataWithPath(InputStream data, String fileType, Vector<String> path) throws Exception {
        URL ocspUrl= new URL(OCSP_URL);
        // create closable http client and assign the certificate interceptor
        CloseableHttpClient httpClient = createSSLClient();
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

    public static void sendDocSigningRequest(InputStream data, GSON.Params params, File output) throws Exception {
        String token = getToken();
        URL ocspUrl= new URL(SIGNING_URL);
        CloseableHttpClient httpClient = createSSLClient();
        URIBuilder uriBuilder = new URIBuilder(ocspUrl.toURI());
        uriBuilder.addParameter("token", token);
        System.out.println("Responder URL: " + uriBuilder.build());
        HttpPost post = new HttpPost(uriBuilder.build());
        Gson gson = new Gson();
        String jsonString = gson.toJson(params);
        StringBody json = new StringBody(jsonString, ContentType.APPLICATION_JSON);
        InputStreamBody input = new InputStreamBody(data, ContentType.APPLICATION_OCTET_STREAM);
        System.err.println(params.toString());
        MultipartEntityBuilder builder =MultipartEntityBuilder.create()
                .addPart("params",
                        json)
                .addPart("data_to_sign", input);

        post.setEntity(builder.build());
        ResponseHandler<InputStream> responseHandler = new ResponseHandler<InputStream>() {

            @Override
            public InputStream handleResponse(HttpResponse response) throws ClientProtocolException, IOException {
                if (response.getStatusLine().getStatusCode() == 200
                        || response.getStatusLine().getStatusCode() == 201) {
                    InputStream result = response.getEntity().getContent();
                    OutputStream stream = new FileOutputStream(output);
                    IOUtils.copy(result, stream);
                    stream.flush();
                    stream.close();
                    result.close();
                    return result;

                }
                return null;
            }
        };
        InputStream response = httpClient.execute(post, responseHandler);


    }
}
