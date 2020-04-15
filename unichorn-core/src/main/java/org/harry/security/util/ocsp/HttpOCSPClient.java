package org.harry.security.util.ocsp;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AccessDescription;
import iaik.x509.X509Certificate;
import iaik.x509.X509ExtensionInitException;
import iaik.x509.extensions.AuthorityInfoAccess;
import iaik.x509.ocsp.OCSPRequest;
import iaik.x509.ocsp.OCSPResponse;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PrivateKey;

/**
 * This class is for get6ting access to a OCSP responder it calls a
 * HTTP connection via HttpClient apache
 * @author Harald Glab-Plhak
 */
public class HttpOCSPClient {

    /**
     * The OCSP client instance
     */
    private static OCSPClient client;

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
     * @param includeExtensions the include certificate extensions flag
     * @return the response from the responder
     */
    public static  OCSPResponse sendOCSPRequest(URL ocspSedrverURL,
            PrivateKey requestorKey,
                                        X509Certificate[] requestorCerts,
                                        X509Certificate[] targetCerts,
                                        boolean includeExtensions) {

        client = new OCSPClient();
        try {
            OCSPRequest request = client.createOCSPRequest(requestorKey, requestorCerts, targetCerts, includeExtensions);
            return getOcspResponseApache(ocspSedrverURL, request);
        } catch (Exception ex){
            throw new IllegalStateException("OCSP request failed", ex);
        }

    }

    /**
     * used to get the underlying client
     * @return the client
     */
    public static OCSPClient getClient() {
        return client;
    }

    /**
     * This method sends the request to the server via apache Http client
     * @param ocspServerURL the URL
     * @param request the request
     * @return the response
     */
    public static OCSPResponse getOcspResponseApache(URL ocspServerURL, OCSPRequest request) {
        CloseableHttpClient httpClient = null;
        try {

            // create closable http client and assign the certificate interceptor
            httpClient = HttpClients.createDefault();
            System.out.println("Responder URL: " + ocspServerURL.toString());
            HttpPost post = new HttpPost(ocspServerURL.toURI());
            post.setHeader("Content-Type","application/ocsp-request");
            post.setHeader("Accept", "application/ocsp-response");
            HttpEntity entity = new ByteArrayEntity(request.getEncoded());
            post.setEntity(entity);
            CloseableHttpResponse response = httpClient.execute(post);
            int code = response.getStatusLine().getStatusCode();
            InputStream respInput = response.getEntity().getContent();
            OCSPResponse ocspResp = new OCSPResponse(respInput);
            respInput.close();
            return ocspResp;
        } catch (Exception ex) {
                throw new IllegalStateException("OCSP request failed", ex);
        }
    }

    /**
     * Get the responder URL from the certificate
     * @param cert the certificate
     * @return the URL from the specified extension
     * @throws X509ExtensionInitException error case
     * @throws MalformedURLException error case
     */
    public static URL getOCSPUrl(X509Certificate cert) throws X509ExtensionInitException, MalformedURLException {
        AuthorityInfoAccess access = (AuthorityInfoAccess)cert.getExtension(ObjectID.certExt_AuthorityInfoAccess);
        AccessDescription description = access.getAccessDescription(ObjectID.ocsp);
        String urlString = description.getUriAccessLocation();
        return new URL(urlString);
    }
}
