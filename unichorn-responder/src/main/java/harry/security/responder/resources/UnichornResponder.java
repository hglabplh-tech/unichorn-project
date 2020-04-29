package harry.security.responder.resources;

import iaik.asn1.CodingException;
import iaik.asn1.structures.AlgorithmID;
import iaik.cms.SecurityProvider;
import iaik.cms.ecc.ECCelerateProvider;
import iaik.security.ec.provider.ECCelerate;
import iaik.security.provider.IAIKMD;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.*;
import iaik.x509.ocsp.net.HttpOCSPRequest;
import iaik.x509.ocsp.utils.ResponseGenerator;
import org.apache.commons.io.IOUtils;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.KeyStoreTool;

import org.pmw.tinylog.Configurator;
import org.pmw.tinylog.Level;
import org.pmw.tinylog.Logger;
import org.pmw.tinylog.writers.FileWriter;



import javax.servlet.*;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;
import javax.ws.rs.core.Response;

import java.io.*;

import java.net.URL;
import java.security.*;

import java.util.*;

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
    private AlgorithmID signatureAlgorithm = AlgorithmID.sha1WithRSAEncryption;



    @Override
    public void init () {
        IAIKMD.addAsProvider();
        ECCelerate ecProvider = ECCelerate.getInstance();
        Security.insertProviderAt(ecProvider, 3);
        SecurityProvider.setSecurityProvider(new ECCelerateProvider());

        Configurator.defaultConfig()
                .writer(new FileWriter("unichorn.log"))
                .locale(Locale.GERMANY)
                .level(Level.TRACE)
                .activate();
    }

   @Override
    public void doPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws ServletException, IOException {
        String output = "Jersey say : ";
        System.out.println("Hallo here I am");
        Logger.trace("enter ocsp method");
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
            Logger.trace("Write stream");
            response.writeTo(servletResponse.getOutputStream());
            Logger.trace("written stream");
            servletResponse.setStatus(Response.Status.OK.getStatusCode());
            servletResponse.setHeader("success", "Seems to be ok:");
            servletResponse.setHeader("Content-Type","application/ocsp-response");
            for(String key: messages.keySet()) {
                servletResponse.addHeader(key, messages.get(key));
            }
        } catch (Exception ex) {
            servletResponse.setStatus(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
            servletResponse.setHeader("error", "Message is:" + ex.getMessage());
            for(String key: messages.keySet()) {
                servletResponse.addHeader(key, messages.get(key));
            }
        }



    }

    @Override
    public void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
       try {
           File trustFile = new File(UnicHornResponderUtil.APP_DIR_TRUST, "trustListPrivate" + ".xml");
           Logger.trace("Trust file is: " + trustFile.getAbsolutePath());
           File crlFile = new File(UnicHornResponderUtil.APP_DIR_TRUST, "privRevokation" + ".crl");
           Logger.trace("CRL list file is: " + crlFile.getAbsolutePath());
           File keyFile = new File(UnicHornResponderUtil.APP_DIR_TRUST, "privKeystore" + ".jks");
           Logger.trace("CRL list file is: " + keyFile.getAbsolutePath());
           String type = request.getHeader("fileType");
           if (type.equals("crl")) {
               OutputStream  out = new FileOutputStream(crlFile);
               InputStream in = request.getInputStream();
               IOUtils.copy(in, out);
               in.close();
               out.close();
           } else if (type.equals("pkcs12")) {

               String passwdHeader = request.getHeader("passwd");
               String decodedString = null;
               if (passwdHeader != null) {
                   byte[] decodedPwd = Base64.getDecoder().decode(passwdHeader.getBytes());
                   decodedString = new String(decodedPwd);
               }
               String storeTypeHeader = request.getHeader("storeType");
               if (storeTypeHeader != null && decodedString != null) {
                   InputStream p12Stream = request.getInputStream();
                   InputStream keyStore = UnicHornResponderUtil.class.getResourceAsStream("/application.jks");
                   KeyStore storeApp = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "JKS");
                   Tuple<PrivateKey, X509Certificate[]> keys = null;
                   keys = KeyStoreTool.getKeyEntry(storeApp, UnichornResponder.ALIAS, "geheim".toCharArray());
                   OutputStream  out = new FileOutputStream(keyFile);
                   IOUtils.copy(p12Stream, out);
                   p12Stream.close();
                   out.close();
                   response.setStatus(Response.Status.CREATED.getStatusCode());
               }
           } else if (type.equals("trust")) {
               InputStream trustStream = request.getInputStream();
               OutputStream  out = new FileOutputStream(trustFile);
               IOUtils.copy(trustStream, out);
               trustStream.close();
               out.close();
               response.setStatus(Response.Status.CREATED.getStatusCode());
           } else {
               response.setStatus(Response.Status.BAD_REQUEST.getStatusCode());
           }
       } catch (Exception ex) {
           response.setStatus(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
       }

    }
    @Override
    public void doGet(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        Logger.trace("Enter get");
        String type = servletRequest.getHeader("fileType");
        Map<String,String> messages = new HashMap<>();
        if (type == null) {

            String path = servletRequest.getPathInfo();
            Logger.trace("The path information is: -> " + path);
            String ocsp = path.substring("/ocsp/".length());
            Logger.trace("The extract information is: -> " + ocsp);

            try {
                byte [] encoded = Base64.getDecoder().decode(ocsp.getBytes());
                Logger.trace("Before getting request");
                OCSPRequest ocspRequest = new OCSPRequest(encoded);
                Logger.trace("After getting request" + ocspRequest.toString(true));
                OCSPResponse response = UnicHornResponderUtil.generateResponse(ocspRequest,
                        copyTo(ocspRequest), responseGenerator, signatureAlgorithm, messages);
                Logger.trace("Write stream");
                response.writeTo(servletResponse.getOutputStream());
                Logger.trace("written stream");
                servletResponse.setStatus(Response.Status.OK.getStatusCode());
                servletResponse.setHeader("success", "Seems to be ok:");
                servletResponse.setHeader("Content-Type","application/ocsp-response");
                for(String key: messages.keySet()) {
                    servletResponse.addHeader(key, messages.get(key));
                }
            } catch (Exception ex) {
                Logger.trace("exception type is ;; " + ex.getClass().getCanonicalName());
                Logger.trace("Error casewith message :: " + ex.getMessage());
                Logger.trace(" has cause " + ((ex.getCause() == null) ? "false" : "true"))
                ;
                servletResponse.setStatus(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
                servletResponse.setHeader("error", "Message is:" + ex.getMessage());
                for(String key: messages.keySet()) {
                    servletResponse.addHeader(key, messages.get(key));
                }
            }

        }
        if (type.equals("crl")) {
                try {
                    InputStream stream = UnicHornResponderUtil.loadActualCRL();
                    OutputStream out = servletResponse.getOutputStream();
                    IOUtils.copy(stream, out);
                    stream.close();
                    servletResponse.setStatus(Response.Status.OK.getStatusCode());
                    return;
                } catch (IOException ex){
                    servletResponse.setStatus(Response.Status.FORBIDDEN.getStatusCode());
                    return;
                }

        } else if (type.equals("trust")){
            File trustFile = new File(UnicHornResponderUtil.APP_DIR_TRUST, "trustListPrivate" + ".xml");
            if (trustFile.exists()) {
                try {
                    FileInputStream stream = new FileInputStream(trustFile);
                    OutputStream out = servletResponse.getOutputStream();
                    IOUtils.copy(stream, out);
                    stream.close();
                    servletResponse.setStatus(Response.Status.OK.getStatusCode());
                    return;
                } catch (IOException ex){
                    servletResponse.setStatus(Response.Status.FORBIDDEN.getStatusCode());
                    return;
                }
            }
        } else {
            servletResponse.setStatus(Response.Status.PRECONDITION_FAILED.getStatusCode());
            return;
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
