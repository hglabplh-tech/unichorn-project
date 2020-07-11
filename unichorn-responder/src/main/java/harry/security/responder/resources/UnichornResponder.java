package harry.security.responder.resources;

import iaik.cms.SecurityProvider;
import iaik.cms.ecc.ECCelerateProvider;
import iaik.security.ec.provider.ECCelerate;
import iaik.security.provider.IAIKMD;
import iaik.utils.Util;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.OCSPRequest;
import iaik.x509.ocsp.OCSPResponse;
import org.apache.commons.io.IOUtils;
import org.harry.security.CommonConst;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.keystores.UnicProvider;
import org.pmw.tinylog.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;
import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static harry.security.responder.resources.UnicHornResponderUtil.*;
import static org.harry.security.CommonConst.APP_DIR_TRUST;


public class UnichornResponder extends HttpServlet {


    public static boolean loggingInitialized = false;








    public static void initReq() {
        LoggerConfigSetter.setLoggerConfig();
        /*  register the providers*/

        Provider iaik = Security.getProvider("IAIK");
        Provider iaikMD = Security.getProvider("IAIKMD");
        Provider ecc = Security.getProvider("ECCelerate");

        if (iaik == null && iaikMD == null && ecc == null) {
            Logger.trace("register base providers IAIK / IAIKMD");
            IAIKMD.addAsProvider();
            Logger.trace("register ECCelerate provider");
            ECCelerate.insertProviderAt(3);
            Logger.trace("register our own keystore spi");
            Security.insertProviderAt(UnicProvider.getInstance(), 4);
            Logger.trace("register ECCelerate security provider");
            SecurityProvider.setSecurityProvider(new ECCelerateProvider());
            Logger.trace("providers are registered");
        } else {
            Logger.trace("The providers are already registered");
        }



    }


   @Override
    public void doPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws ServletException, IOException {
       initReq();
        String output = "Jersey say : ";
        Logger.trace("Hallo here I am");
        Logger.trace("enter ocsp method");
        Map<String,String> messages = new HashMap<>();
        messages.put("pre", "pre started: ");
        try {
            HttpServletRequestWrapper wrapper = new HttpServletRequestWrapper(servletRequest);
            InputStream stream = servletRequest.getInputStream();
            String indicator = (stream == null) ? "null" : "not null";
            Logger.trace("pre request read stream is: " + indicator);
            OCSPRequest ocspRequest = new OCSPRequest(stream);

            Logger.trace( "request read");
            OCSPResponse response = UnicHornResponderUtil.generateResponse(ocspRequest,
                    copyTo(ocspRequest));
            Logger.trace("Write stream");
            response.writeTo(servletResponse.getOutputStream());
            Logger.trace("written stream");
            servletResponse.setStatus(Response.Status.OK.getStatusCode());
            Logger.trace("Seems to be ok:");
            servletResponse.setHeader("Content-Type","application/ocsp-response");
            for(String key: messages.keySet()) {
                servletResponse.addHeader(key, messages.get(key));
            }
        } catch (Exception ex) {
            OCSPResponse response = new OCSPResponse(OCSPResponse.malformedRequest);
            response.writeTo(servletResponse.getOutputStream());
            servletResponse.setStatus(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
            Logger.trace("Error Message is:" + ex.getMessage());
            for(String key: messages.keySet()) {
                servletResponse.addHeader(key, messages.get(key));
            }
        }



    }

    @Override
    public void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
       try {
           initReq();
           File trustFile = new File(APP_DIR_TRUST, "trustListPrivate" + ".xml");
           Logger.trace("Trust file is: " + trustFile.getAbsolutePath());
           File crlFile = new File(APP_DIR_TRUST, "privRevokation" + ".crl");
           Logger.trace("CRL list file is: " + crlFile.getAbsolutePath());
           File keyFile = new File(APP_DIR_TRUST, CommonConst.PRIV_KEYSTORE);
           Logger.trace("Key Store file is: " + keyFile.getAbsolutePath());
           String type = request.getHeader("fileType");
           if (type.equals("crl")) {
               OutputStream  out = new FileOutputStream(crlFile);
               InputStream in = request.getInputStream();
               IOUtils.copy(in, out);
               in.close();
               out.close();
               X509CRL crl = readCrl(new FileInputStream(crlFile));
               Tuple<PrivateKey, X509Certificate[]> keys =getPrivateKeyX509CertificateTuple();
               crl.setIssuerDN(keys.getSecond()[0].getIssuerDN());
               crl.sign(keys.getFirst());
           } else if (type.equals("UnicP12")) {

               String passwdHeader = request.getHeader("passwd");
               String passwdUser = request.getHeader("passwdUser");
               String decodedUser = new String(Util.fromBase64String(passwdUser));
               String decodedString = null;
               if (passwdHeader != null) {
                   byte[] decodedPwd = Base64.getDecoder().decode(passwdHeader.getBytes());
                   decodedString = new String(decodedPwd);
                   encryptPassword("pwdFile", decodedString);
               }
               String storeTypeHeader = request.getHeader("storeType");
               if (storeTypeHeader != null && decodedString != null) {
                   File temp = saveToTemp(request.getInputStream());
                   InputStream p12Stream = new FileInputStream(temp);
                   Logger.trace("Before loading keystore");
                   KeyStore storeToApply = KeyStoreTool.loadStore(p12Stream,
                           decodedUser.toCharArray(), storeTypeHeader);
                   Logger.trace("Before calling merge");
                   applyKeyStore(keyFile, storeToApply, decodedString, decodedUser, storeTypeHeader);
                   Logger.trace("After calling merge --> created");
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
           Logger.trace("Error case load trust or pkcs7 or crl : " +  ex.getMessage());
           response.setStatus(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
       }

    }
    @Override
    public void doGet(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        initReq();
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
                        copyTo(ocspRequest));
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
            File trustFile = new File(APP_DIR_TRUST, "trustListPrivate" + ".xml");
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
        } else if (type.equals("UnicP12")){
            File keyFile = new File(APP_DIR_TRUST, "privKeystore" + ".p12");
            if (keyFile.exists()) {
                try {
                    FileInputStream stream = new FileInputStream(keyFile);
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
        } catch (Exception ex) {
            throw new IllegalStateException("cannot copy stream", ex);
        }
    }

    public File saveToTemp(InputStream input) throws IOException {
        File tempFile = File.createTempFile("upload", ".dat");
        tempFile.deleteOnExit();
        FileOutputStream out = new FileOutputStream(tempFile);
        IOUtils.copy(input, out);
        out.flush();
        input.close();
        out.close();
        return tempFile;
    }

    public static boolean isLoggingInitialized() {
        boolean result = loggingInitialized;
        loggingInitialized = true;
        return result;
    }


}
