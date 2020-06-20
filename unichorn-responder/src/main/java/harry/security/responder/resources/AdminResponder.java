package harry.security.responder.resources;

import com.google.gson.Gson;
import iaik.asn1.structures.AlgorithmID;
import iaik.utils.Util;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.utils.ResponseGenerator;
import org.apache.commons.io.FileDeleteStrategy;
import org.apache.commons.io.IOUtils;
import org.harry.security.util.*;
import org.harry.security.util.certandkey.GSON;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.json.JSONException;
import org.pmw.tinylog.Logger;

import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;
import javax.ws.rs.core.Response;
import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static harry.security.responder.resources.UnicHornResponderUtil.*;
import static org.harry.security.CommonConst.*;
import static org.harry.security.util.CertificateWizzard.PROP_STORE_NAME;
import static org.harry.security.util.CertificateWizzard.PROP_TRUST_NAME;

@WebServlet
@MultipartConfig(
        location = "c:\\tmp",
        fileSizeThreshold   = 0,  // 10 MB
        maxFileSize         = -1L, // 100 MB
        maxRequestSize      = -1L // 150 MB
)
public class AdminResponder extends HttpServlet {


    /**
     * Use an OCSP ResponseGenerator for request parsing / response generation.
     */
    private ResponseGenerator responseGenerator;
    /**
     * Algorithm to be used for signing the response.
	 */
    private AlgorithmID signatureAlgorithm = AlgorithmID.sha1WithRSAEncryption;


   @Override
    public void doPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws ServletException, IOException {
       UnichornResponder.initReq();
       String output = "Jersey say : ";
       Logger.trace("Hallo here I am");
       Logger.trace("enter admin post");


       boolean success = isAuthenticated(servletRequest);

       if(!success) {
           Logger.trace("NOT AUTH");
           servletResponse.setStatus(Response.Status.FORBIDDEN.getStatusCode());
           return;
       }
       Logger.trace("AUTHENTICATED!!!");
   try {
       GSON.Params jInput = readJSon(servletRequest);
       if (jInput.parmType.equals("saveProps")) {
           saveAppProperties(servletRequest, servletResponse, jInput);
       } else if (jInput.parmType.equals("initApplication")) {
           String error = null;
           String passwdUser = servletRequest.getParameter("passwdUser");
           if (passwdUser == null) {
               error = "param passwdUser not set;;";
           }
           String passwdHeader = servletRequest.getParameter("passwd");
           if (passwdHeader == null) {
               error = error + "param passwd not set;;";
           }
           String storeTypeHeader = servletRequest.getParameter("storeType");
           if (storeTypeHeader == null) {
               error = error + "param storeType not set;;";
           }
           if (error != null) {
               Logger.trace("Parameters error(s) -> " + error);
               servletResponse.setStatus(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
               return;
           }
           initApplication(servletRequest, passwdUser, passwdHeader, storeTypeHeader);
       } else if (jInput.parmType.equals("setSigningStore")) {
           saveSignKeyStore(servletRequest, servletResponse, jInput);

       } else if (jInput.parmType.equals("resignCRL")) {
           resignCRL(servletResponse);
       } else if (jInput.parmType.equals("cleanupPreparedResp")) {
           File toDelete = new File(APP_DIR_WORKING, "responses.ser");
           Logger.trace("cleanupPreparedResp : delete file: " + toDelete.getAbsolutePath());
           if (toDelete.exists()) {
               FileDeleteStrategy.FORCE.delete(toDelete);
               Logger.trace("cleanupPreparedResp : delete file success : " + toDelete.getAbsolutePath());
           }
       }

   } catch (Exception ex) {
        servletResponse.setStatus(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
        Logger.trace("Error Message is:" + ex.getMessage());
        Logger.trace(ex);

   }





    }

    private void initApplication(HttpServletRequest servletRequest,
                                 String passwdUser, String passwdHeader, String storeTypeHeader) throws IOException, ServletException {
        File keystore = new File(APP_DIR, PROP_STORE_NAME);
        Logger.trace("Write file: -> " + keystore.getAbsolutePath());
        keystore.delete();
        FileOutputStream out = new FileOutputStream(keystore);
        Part keyStorePart = servletRequest.getPart("keystore");
        IOUtils.copy(keyStorePart.getInputStream(), out);
        out.flush();
        out.close();
        Logger.trace("Written file: -> " + keystore.getAbsolutePath());
        File trustFile = new File(APP_DIR_TRUST, PROP_TRUST_NAME);
        Logger.trace("Write file: -> " + trustFile.getAbsolutePath());
        trustFile.delete();
        out = new FileOutputStream(trustFile);
        Part trustListPart = servletRequest.getPart("trustlist");
        IOUtils.copy(trustListPart.getInputStream(), out);
        out.flush();
        out.close();
        Logger.trace("Written file: -> " + trustFile.getAbsolutePath());

        File propFile = new File(APP_DIR, PROP_FNAME);
        Logger.trace("Write file: -> " + propFile.getAbsolutePath());
        propFile.delete();
        out = new FileOutputStream(propFile);
        Part propertiesPart = servletRequest.getPart("properties");
        IOUtils.copy(propertiesPart.getInputStream(), out);
        out.flush();
        out.close();
        Logger.trace("Written file: -> " + propFile.getAbsolutePath());
        applyAppKeyStore(keystore, passwdUser, passwdHeader, storeTypeHeader);
    }

    private void applyAppKeyStore(File keystore,
                                  String passwdUser, String passwdHeader,
                                  String storeTypeHeader) throws IOException {
        File keyFile = new File(APP_DIR_TRUST, PRIV_KEYSTORE);
        String decodedUser = new String(Util.fromBase64String(passwdUser));
        byte[] decodedPwd = Base64.getDecoder().decode(passwdHeader.getBytes());
        String decodedString = new String(decodedPwd);
        Logger.trace("Before loading keystore");
        InputStream p12Stream = new FileInputStream(keystore);
        KeyStore storeToApply = KeyStoreTool.loadStore(p12Stream,
                decodedUser.toCharArray(), storeTypeHeader);
        p12Stream.close();
        Logger.trace("Before calling merge");
        applyKeyStore(keyFile, storeToApply, decodedString, decodedUser, storeTypeHeader);
        Logger.trace("After calling merge --> created");
    }

    private boolean isAuthenticated(HttpServletRequest servletRequest) throws IOException {
        boolean success = false;
        String tokIN = servletRequest.getParameter("token");
        File tokFile = new File(APP_DIR, "adminToken.bytes");
        if (tokFile.exists()) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            IOUtils.copy(new FileInputStream(tokFile), out);
            out.flush();
            String token = new String(out.toByteArray());
            if (tokIN.equalsIgnoreCase(token)) {
                success = true;
            }
        } else {
            success = false;
        }
        return success;
    }

    @Override
    public void doGet(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws ServletException, IOException {
        UnichornResponder.initReq();
       String action = servletRequest.getParameter("action");
        if (action != null & action.equals("token")) {
            String password = decryptPassword("pwdServiceFile");
            String passwdHeader = servletRequest.getHeader("passwd");
            String decodedString = null;
            if (passwdHeader != null) {
                byte[] decodedPwd = Base64.getDecoder().decode(passwdHeader.getBytes());
                decodedString = new String(decodedPwd);
                if (!decodedString.equals(password)) {
                    servletResponse.setStatus(Response.Status.FORBIDDEN.getStatusCode());
                    return;
                }
            } else {
                servletResponse.setStatus(Response.Status.FORBIDDEN.getStatusCode());
                return;
            }
            File tokFile = new File(APP_DIR, "adminToken.bytes");
            if (!tokFile.exists()) {
                String token = UUID.randomUUID().toString();
                ExecutorService executor = Executors.newFixedThreadPool(5);

                Future<?> task = executor.submit(new TokenThread(tokFile, token));
                ByteArrayInputStream input = new ByteArrayInputStream(token.getBytes());
                IOUtils.copy(input, servletResponse.getOutputStream());
                servletResponse.setStatus(Response.Status.CREATED.getStatusCode());
                Logger.trace("Written Token file Admin");
            } else{
                IOUtils.copy(new FileInputStream(tokFile),servletResponse.getOutputStream());
                Logger.trace("Read Token file Admin");
                servletResponse.setStatus(Response.Status.CREATED.getStatusCode());

            }
        }
    }



    public static void saveAppProperties(HttpServletRequest servletRequest,
                                         HttpServletResponse servletResponse, GSON.Params jInput) {
       try {
           Part part = servletRequest.getPart("data_to_sign");
           FileOutputStream propFile = new FileOutputStream(new File(APP_DIR, PROP_FNAME));
           IOUtils.copy(part.getInputStream(), propFile);
           propFile.close();
           servletResponse.setStatus(Response.Status.CREATED.getStatusCode());
       } catch (Exception ex) {
           Logger.trace("Application properties saving failed with" +ex.getMessage());
           throw new IllegalStateException("properties file storing failed", ex);
       }
    }

    public static void saveSignKeyStore(HttpServletRequest servletRequest,
                                         HttpServletResponse servletResponse, GSON.Params jInput) {
        try {
            Part part = servletRequest.getPart("data_to_sign");
            FileOutputStream keyFile = new FileOutputStream(new File(APP_DIR, PROP_SIGNSTORE));
            IOUtils.copy(part.getInputStream(), keyFile);
            keyFile.close();
            servletResponse.setStatus(Response.Status.CREATED.getStatusCode());
        } catch (Exception ex) {
            Logger.trace("Application properties saving failed with" +ex.getMessage());
            throw new IllegalStateException("properties file storing failed", ex);
        }
    }
    public static void resignCRL(HttpServletResponse servletResponse) {
        try {
            InputStream crlIN = loadActualCRL();
            X509CRL crl = readCrl(crlIN);
            KeyStore store =
                     KeyStoreTool.loadAppStore();
            Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
            crl.setIssuerDN(keys.getSecond()[1].getSubjectDN());
            crl.sign(keys.getFirst());
            servletResponse.setStatus(Response.Status.OK.getStatusCode());
        } catch (Exception ex) {
            Logger.trace("Application properties saving failed with" +ex.getMessage());
            throw new IllegalStateException("properties file storing failed", ex);
        }
    }

    public GSON.Params readJSon(HttpServletRequest request) {
        StringBuffer jb = new StringBuffer();
        String line = null;
        try {
            Logger.trace("Read Json");
            Part part = request.getPart("params");
            InputStream stream = part.getInputStream();
            Reader in = new InputStreamReader(stream);
            BufferedReader reader = new BufferedReader(in);
            while ((line = reader.readLine()) != null)
                jb.append(line);
            Logger.trace("Read Json ready;" + jb.toString());
        } catch (Exception ex) {
            Logger.trace("Error: " + ex.getMessage());
            Logger.trace(ex);
        }

        try {
            Gson gson = new Gson();
            GSON.Params jsonObject = gson.fromJson(jb.toString(), GSON.Params.class);
            return jsonObject;
        } catch (JSONException ex) {
            Logger.trace("Error: " + ex.getMessage());
            Logger.trace(ex);
            throw new IllegalStateException("Error parsing JSON request string");
        }
    }




}
