package org.harry.security.util;

import iaik.asn1.CodingException;
import iaik.asn1.structures.AlgorithmID;
import iaik.tsp.MessageImprint;
import iaik.tsp.TimeStampReq;
import iaik.tsp.transport.http.TspHttpClient;
import iaik.tsp.transport.http.TspHttpResponse;
import iaik.xml.crypto.xades.impl.HTTPTSPTimeStampProcessor;
import iaik.xml.crypto.xades.impl.TSPTimeStampProcessor;
import iaik.xml.crypto.xades.timestamp.TimeStampException;
import iaik.xml.crypto.xades.timestamp.TimeStampProcessor;
import iaik.xml.crypto.xades.timestamp.TimeStampToken;
import iaik.xml.crypto.xades.timestamp.impl.TSPTimeStampTokenImpl;
import org.apache.commons.io.IOUtils;
import org.harry.security.util.httpclient.SSLUtils;
import org.pmw.tinylog.Logger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.xml.crypto.OctetStreamData;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;

import static org.harry.security.CommonConst.TSP_URL;

public class SimpleTimeStampProcessor implements TimeStampProcessor {

    protected URL url;

    public SimpleTimeStampProcessor(String var1) throws MalformedURLException {
        this.url = new URL(var1);
    }

    @Override
    public TimeStampToken timeStamp(OctetStreamData octetStreamData) throws TimeStampException {
        try {
            if (url.equals(new URL(TSP_URL))) {
                TimeStampReq req = createTimeStampRequest(octetStreamData);
                TspHttpResponse response = sendAndReceiveData(req, url.toExternalForm());
                iaik.tsp.TimeStampToken token =  response.getTimeStampResp().getTimeStampToken();
                return new TSPTimeStampTokenImpl(token);
            } else {
                TimeStampProcessor processor = null;
                try {
                    processor = new HTTPTSPTimeStampProcessor(url.toExternalForm());
                } catch (MalformedURLException e) {

                }
                return processor.timeStamp(octetStreamData);
            }
        } catch (Exception ex) {
            throw new IllegalStateException("time stamp processor failed", ex);
        }
    }

    public TspHttpResponse sendAndReceiveData(TimeStampReq request, String url) throws Exception {

        if (request == null) {
            throw new NullPointerException("Argument \"request\" must not be null");
        }

        Logger.debug("Client connects to TSP server at: " + url);
        SSLContext sslContext = SSLUtils.createStandardContext();
        SSLContext.setDefault(sslContext);
        javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String s, SSLSession sslSession) {
                return true;
            }
        });
        HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
        conn.setDoOutput(true);
        TspHttpClient tspHttpClient = new TspHttpClient(conn);



        TspHttpResponse response = tspHttpClient.sendRequest(request);

        Logger.debug("[" + url + "]" + " Response received");
        Logger.debug("[" + url + "]" + " Connection closed");

        return response;
    }

    /**
     * Creates a time stamp request
     */
    private static TimeStampReq createTimeStampRequest(OctetStreamData octetStreamData) {
        byte[] hashed_message = null;
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            IOUtils.copy(octetStreamData.getOctetStream(), output);
            hashed_message = MessageImprint.calculateHash(output.toByteArray(), AlgorithmID.sha1);
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            return null;
        }

        MessageImprint imprint = new MessageImprint(AlgorithmID.sha1, hashed_message);
        TimeStampReq request = new TimeStampReq();
        request.setMessageImprint(imprint);
        request.setCertReq(true);
        return request;
    }
}
