package harry.security.responder.resources;

import iaik.asn1.CodingException;
import iaik.asn1.structures.AlgorithmID;
import iaik.tsp.MessageImprint;
import iaik.tsp.TimeStampReq;
import iaik.tsp.transport.http.TspHttpClient;
import iaik.tsp.transport.http.TspHttpResponse;
import org.junit.Test;
import org.pmw.tinylog.Logger;

import java.io.IOException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;

public class TimeStampTest {

    protected static final String MESSAGE = "Message to be time stamped";

    @Test
    public void getTimestampOk() throws Exception  {
        String tspUrl = "http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/tsp";
        sendAndReceiveData(createTimeStampRequest(), tspUrl);
    }

    public TspHttpResponse sendAndReceiveData(TimeStampReq request, String url) throws NullPointerException, IOException,
            CodingException {

        if (request == null) {
            throw new NullPointerException("Argument \"request\" must not be null");
        }

        Logger.debug("Client connects to TSP server at: " + url);
        TspHttpClient tspHttpClient = new TspHttpClient(new URL(url));



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
