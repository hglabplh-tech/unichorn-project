package org.harry.security.util.ocsp;

import iaik.x509.X509Certificate;
import iaik.x509.ocsp.OCSPRequest;
import iaik.x509.ocsp.OCSPResponse;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.security.PrivateKey;
import java.util.Base64;

import static org.harry.security.util.httpclient.ClientFactory.createSSLClient;

/**
 * This class is for get6ting access to a OCSP responder it calls a
 * HTTP connection via HttpClient apache
 * @author Harald Glab-Plhak
 */
public class HttpOCSPClient {

    /**
     * The OCSP client instance
     */
    private static OCSPCRLClient client;

    /**
     * flag to tell that we are initialized
     */
    private static boolean factoryInitialized = false;

    /**
     * This method sends a request to a given responder
     * @param ocspSedrverURL the URL
     * @param requestorKey the requestor private key this is nullable
     * @param requestorCerts the requestor certificates this is nullable
     * @param targetCerts the target certificates which have to be checked
     * @param additionalExts
     * @return the response from the responder
     */
    public static  OCSPResponse sendOCSPRequest(String ocspSedrverURL,
                                                PrivateKey requestorKey,
                                                X509Certificate[] requestorCerts,
                                                X509Certificate[] targetCerts,
                                                int type, boolean isAltRespRequested, boolean additionalExts) {

        client = new OCSPCRLClient();
        try {
            String altResponder= null;
            if (isAltRespRequested) {
             altResponder = OCSPCRLClient.getOCSPUrl(targetCerts[0]);
            }
            OCSPRequest request = client.createOCSPRequest(requestorKey, requestorCerts,
                    targetCerts, type, altResponder, additionalExts);
            OCSPResponse response;

            response = getOcspResponsePOSTApache(ocspSedrverURL, request);

            return response;
        } catch (Exception ex){
            throw new IllegalStateException("OCSP request failed", ex);
        }

    }

    /**
     * used to get the underlying client
     * @return the client
     */
    public static OCSPCRLClient getClient() {
        return client;
    }

    /**
     * This method sends the request to the server via apache Http client
     * @param ocspServerURL the URL
     * @param request the request
     * @return the response
     */
    public static OCSPResponse getOcspResponsePOSTApache(String ocspServerURL, OCSPRequest request) {
        CloseableHttpClient httpClient = null;
        try {

            // create closable http client and assign the certificate interceptor
            httpClient = createSSLClient();
            System.out.println("Responder URL: " + ocspServerURL.toString());
            HttpPost post = new HttpPost(new URL(ocspServerURL).toURI());
            post.setHeader("Content-Type","application/ocsp-request");
            post.setHeader("Accept", "application/ocsp-response");
            HttpEntity entity = new ByteArrayEntity(request.getEncoded());
            post.setEntity(entity);
            CloseableHttpResponse response = httpClient.execute(post);
            int code = response.getStatusLine().getStatusCode();
            System.out.println("ocsp ends with: " + code);
            Header [] allheader = response.getAllHeaders();
            if (code == 200) {
                InputStream respInput = response.getEntity().getContent();
                OCSPResponse ocspResp = new OCSPResponse(respInput);
                respInput.close();
                return ocspResp;
            } else {
                return null;
            }
        } catch (Exception ex) {
                throw new IllegalStateException("OCSP request failed", ex);
        }
    }

    /**
     * This method sends the request to the server via apache Http client
     * @param ocspServerURL the URL
     * @param request the request
     * @return the response
     */
    public static OCSPResponse getOcspResponseGETApache(String ocspServerURL, OCSPRequest request) {
        CloseableHttpClient httpClient = null;
        try {

            // create closable http client and assign the certificate interceptor
            httpClient = HttpClients.createDefault();
            System.out.println("Responder URL: " + ocspServerURL.toString());
            byte [] encoded = Base64.getEncoder().encode(request.getEncoded());
            String encodedString = new String(encoded);
            String ocspRequestUrl = ocspServerURL + "/" + encodedString;
            HttpGet get = new HttpGet(new URI(ocspRequestUrl));
            String result = get.getRequestLine().getUri();
            get.setHeader("Content-Type","application/ocsp-request");
            get.setHeader("Accept", "application/ocsp-response");

            String reqLine = get.getRequestLine().getUri();

            CloseableHttpResponse response = httpClient.execute(get);
            int code = response.getStatusLine().getStatusCode();
            System.out.println("ocsp ends with: " + code);
            Header [] allheader = response.getAllHeaders();
            if (code == 200) {
                InputStream respInput = response.getEntity().getContent();
                OCSPResponse ocspResp = new OCSPResponse(respInput);

                return ocspResp;
            } else {
                return null;
            }
        } catch (Exception ex) {
            throw new IllegalStateException("OCSP request failed", ex);
        }
    }


}
