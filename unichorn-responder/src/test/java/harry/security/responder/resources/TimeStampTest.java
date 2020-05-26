package harry.security.responder.resources;

import iaik.asn1.CodingException;
import iaik.asn1.structures.AlgorithmID;
import iaik.tsp.MessageImprint;
import iaik.tsp.TSTInfo;
import iaik.tsp.TimeStampReq;
import iaik.tsp.TimeStampToken;
import iaik.tsp.transport.http.TspHttpClient;
import iaik.tsp.transport.http.TspHttpResponse;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.junit.Test;
import org.pmw.tinylog.Logger;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;

import static org.harry.security.CommonConst.TSP_URL;

public class TimeStampTest {

    protected static final String MESSAGE = "Message to be time stamped";

    @Test
    public void getTimestampOk() throws Exception  {
        TspHttpResponse response = sendAndReceiveData(createTimeStampRequest(), TSP_URL);
        TimeStampToken token = response.getTimeStampResp().getTimeStampToken();
        TSTInfo info = token.getTSTInfo();
        Date date = info.getGenTime();
        SimpleDateFormat fmt = new SimpleDateFormat("\"dd/MM/yyyy'T'HH:mm:ss:SSS\"");
        System.out.println("Atomic TimeStamp: " + fmt.format(date));
    }

    public TspHttpResponse sendAndReceiveData(TimeStampReq request, String url) throws NullPointerException, IOException,
            CodingException {

        if (request == null) {
            throw new NullPointerException("Argument \"request\" must not be null");
        }

        Logger.debug("Client connects to TSP server at: " + url);
        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
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
    private static TimeStampReq createTimeStampRequest() {
        byte[] hashed_message = null;
        try {
            hashed_message = MessageImprint.calculateHash(MESSAGE.getBytes(), AlgorithmID.sha1);
        } catch (NoSuchAlgorithmException e) {
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
