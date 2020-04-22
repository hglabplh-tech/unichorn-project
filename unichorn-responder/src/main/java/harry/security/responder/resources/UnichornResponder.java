package harry.security.responder.resources;

import iaik.asn1.structures.AlgorithmID;
import iaik.x509.ocsp.*;
import iaik.x509.ocsp.utils.ResponseGenerator;
import org.codehaus.classworlds.Configurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;


import javax.servlet.*;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;

import java.io.*;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import static iaik.x509.ocsp.CertStatus.*;
import static org.harry.security.util.certandkey.CertWriterReader.loadSecrets;


public class UnichornResponder extends HttpServlet {

    

    public static final String ALIAS = "Common T-Systems Green TeamUserRSA";
    /**
     * Use an OCSP ResponseGenerator for request parsing / response generation.
     */
    private ResponseGenerator responseGenerator;
    /**
     * Algorithm to be used for signing the response.
	 */
    private AlgorithmID signatureAlgorithm = AlgorithmID.sha256WithRSAEncryption;

    private Logger LOG = LoggerFactory.getLogger(UnichornResponder.class);


   @Override
    public void doPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws ServletException, IOException {
        String output = "Jersey say : ";
        System.out.println("Hallo here I am");
        LOG.trace("enter ocsp method");
        Map<String,String> messages = new HashMap<>();
        messages.put("pre", "pre started: ");
        try {
            HttpServletRequestWrapper wrapper = new HttpServletRequestWrapper(servletRequest);
            InputStream stream = servletRequest.getInputStream();
            String indicator = (stream == null) ? "null" : "not null";
            messages.put("info-pre", "pre request read stream is: " + indicator);
            OCSPRequest ocspRequest = new OCSPRequest(stream);

            messages.put("info-pre2", "request read");

            OCSPResponse response = UnicHornResponderUtil.generateResponse(ocspRequest,
                    copyTo(ocspRequest), responseGenerator, signatureAlgorithm, messages);
            LOG.trace("Write stream");
            response.writeTo(servletResponse.getOutputStream());
            LOG.trace("written stream");
            servletResponse.setStatus(200);
            servletResponse.setHeader("success", "Seems to be ok:");
            for(String key: messages.keySet()) {
                servletResponse.addHeader(key, messages.get(key));
            }
        } catch (Exception ex) {
            servletResponse.setStatus(400);
            servletResponse.setHeader("error", "Message is:" + ex.getMessage());
            for(String key: messages.keySet()) {
                servletResponse.addHeader(key, messages.get(key));
            }
        }



    }


    private ByteArrayInputStream copyTo(OCSPRequest request) {
       try {
           ByteArrayOutputStream out = new ByteArrayOutputStream();
           request.writeTo(out);
           ByteArrayInputStream bufferIN = new ByteArrayInputStream(out.toByteArray());
           out.close();
           return bufferIN;
       } catch(Exception ex) {
           throw new IllegalStateException("cannot copy stream", ex);
       }
   }




}
