package harry.security.responder.resources;

import com.google.gson.Gson;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.AttributeValue;
import iaik.cms.SignedData;
import iaik.pdf.parameters.PadesBESParameters;
import iaik.pkcs.pkcs10.CertificateRequest;
import iaik.pkcs.pkcs8.EncryptedPrivateKeyInfo;
import iaik.pkcs.pkcs9.ChallengePassword;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.attr.AttributeCertificate;
import iaik.x509.ocsp.utils.ResponseGenerator;
import org.apache.commons.io.IOUtils;
import org.harry.security.util.*;
import org.harry.security.util.algoritms.DigestAlg;
import org.harry.security.util.algoritms.SignatureAlg;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.CSRHandler;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.certandkey.GSON;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.json.JSONException;
import org.pmw.tinylog.Logger;

import javax.activation.DataSource;
import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;
import javax.ws.rs.core.Response;
import java.io.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static harry.security.responder.resources.UnicHornResponderUtil.*;
import static org.harry.security.CommonConst.*;

@WebServlet
@MultipartConfig(
        location = "c:\\tmp",
        fileSizeThreshold   = 0,  // 10 MB
        maxFileSize         = -1L, // 100 MB
        maxRequestSize      = -1L // 150 MB
)
public class SigningResponder extends HttpServlet {



    public static final String ALIAS = "b998b1f7-04fe-42c6-8284-9fb21e604b60UserRSA";

    public static final String PROP_FNAME = "application.properties";

    public static final String PROP_SIGNSTORE = "signStore.p12";



    /**
     * Use an OCSP ResponseGenerator for request parsing / response generation.
     */
    private ResponseGenerator responseGenerator;
    /**
     * Algorithm to be used for signing the response.
	 */
    private AlgorithmID signatureAlgorithm = AlgorithmID.sha1WithRSAEncryption;


    //@Override
  /**  public void init () {
        Logger.trace("register IAIK providers");
        IAIKMD.addAsProvider();
        ECCelerate.insertProviderAt(3);
        SecurityProvider.setSecurityProvider(new ECCelerateProvider());
        Logger.trace("register IAIK providers success");
        //

        Configurator.defaultConfig()
                .writer(new FileWriter("unichorn.log"))
                .locale(Locale.GERMANY)
                .level(Level.TRACE)
                .activate();
    } **/


   @Override
    public void doPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws IOException, ServletException   {
       init ();
        String output = "Jersey say : ";
        Logger.trace("Hallo here I am");
        Logger.trace("enter ocsp method");


       boolean success = isAuthenticated(servletRequest);
       if(!success) {
            servletResponse.setStatus(Response.Status.FORBIDDEN.getStatusCode());
            return;
        }
   try {
       GSON.Params jInput = readJSon(servletRequest);
       if (jInput.parmType.equals("docSign")) {
           docSigning(servletRequest, servletResponse, jInput);
       }else if (jInput.parmType.equals("docVerify")) {
           docVerify(servletRequest, servletResponse, jInput);
       } else if (jInput.parmType.equals("docCompress")) {
           docSigning(servletRequest, servletResponse, jInput);
       } else if (jInput.parmType.equals("certSign")) {
           Part part = servletRequest.getPart("data_to_sign");
           CertificateRequest certReq = new CertificateRequest(part.getInputStream());
           Part info = servletRequest.getPart("info");
           InputStream infoStream = null;
           if (info != null) {
               Logger.trace("Read private key encrypted");
               infoStream = info.getInputStream();
           }
           PrivateKey userKey = null;
           Logger.trace("Check challenge password success");
           if (infoStream != null) {
               Logger.trace("Read private key encrypted");
               ByteArrayOutputStream infoOut = new ByteArrayOutputStream();
               IOUtils.copy(infoStream, infoOut);
               // decode, decrypt, unwrap
               EncryptedPrivateKeyInfo epki =
                       new EncryptedPrivateKeyInfo(infoOut.toByteArray());

               ChallengePassword challengePassword = (ChallengePassword)
                       certReq.getAttributeValue(ObjectID.challengePassword);
               userKey = epki.decrypt(challengePassword.getPassword());
               Logger.trace("private key decrypted success");
           }
           InputStream input = part.getInputStream();
           Tuple<PrivateKey, X509Certificate[]> resultInfo  = CSRHandler.certSigning(certReq, userKey);
           String passwd = decryptPassword("pwdFile");
           File keyFile = new File(APP_DIR_TRUST, "privKeystore" + ".p12");
           File tempKeyFile = File.createTempFile("keystore", ".p12");
           tempKeyFile.delete();
           applyKeyStore(keyFile, resultInfo.getFirst(),
                   resultInfo.getSecond(),
                   passwd, "PKCS12");
           applyKeyStore(tempKeyFile, resultInfo.getFirst(),
                   resultInfo.getSecond(),
                   "changeit", "PKCS12");
           FileInputStream keyStore = new FileInputStream(tempKeyFile);

           if (keyStore != null) {
               IOUtils.copy(keyStore, servletResponse.getOutputStream());
               servletResponse.setStatus(Response.Status.CREATED.getStatusCode());
           } else {
               servletResponse.setStatus(Response.Status.FORBIDDEN.getStatusCode());
               Logger.trace("challenge password wrong");
           }
       }

   } catch (Exception ex) {
       servletResponse.setStatus(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
       Logger.trace("Error Message is:" + ex.getMessage());
       Logger.trace(ex);
   }





    }

    private boolean isAuthenticated(HttpServletRequest servletRequest) throws IOException {
        boolean success = false;
        String tokIN = servletRequest.getParameter("token");
        File tokFile = new File(APP_DIR, "token.bytes");
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
       String action = servletRequest.getParameter("action");
        if (action != null & action.equals("passwd")) {
            String fname = UUID.randomUUID().toString();
            File out = new File(APP_DIR_WORKING, fname);
            FileOutputStream outstream = new FileOutputStream(out);
            outstream.write(fname.getBytes());
            servletResponse.getOutputStream().write(fname.getBytes());
            servletResponse.setStatus(Response.Status.CREATED.getStatusCode());
        } else if (action != null & action.equals("token")) {
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
            File tokFile = new File(APP_DIR, "token.bytes");
            if (!tokFile.exists()) {
                String token = UUID.randomUUID().toString();
                ExecutorService executor = Executors.newFixedThreadPool(5);

                Future<?> task = executor.submit(new TokenThread(tokFile, token));
                ByteArrayInputStream input = new ByteArrayInputStream(token.getBytes());
                IOUtils.copy(input, servletResponse.getOutputStream());
                servletResponse.setStatus(Response.Status.CREATED.getStatusCode());
                Logger.trace("Written Token file Signing");
            } else{
                IOUtils.copy(new FileInputStream(tokFile),servletResponse.getOutputStream());
                servletResponse.setStatus(Response.Status.CREATED.getStatusCode());
                Logger.trace("Read Token file Signing");
            }
        }
    }


    private void docSigning(HttpServletRequest servletRequest, HttpServletResponse servletResponse, GSON.Params jInput) throws KeyStoreException, IOException, ServletException {
       try {
           Logger.trace("read params....");
           String sigType = jInput.signing.signatureType;
           Logger.trace("type is: " + sigType);
           int mode = jInput.signing.mode;
           String sigAlg = jInput.signing.signatureAlgorithm;
           String digestAlg = jInput.signing.digestAlgorithm;
           AttributeCertificate attrCert = null;
           if (jInput.signing.attributeCert != null) {
               byte[] encoded = Util.fromBase64String(jInput.signing.attributeCert);
               attrCert = new AttributeCertificate(encoded);
           }
           Logger.trace("mode is: " + mode);
           SigningBean.Mode smode;
           if (mode == SignedData.EXPLICIT) {
               smode = SigningBean.Mode.EXPLICIT;
           } else {
               smode = SigningBean.Mode.IMPLICIT;
           }
           File signStore = new File(APP_DIR, PROP_SIGNSTORE);
           boolean found = false;
           String foundID = null;
           KeyStore store = null;
           String password = decryptPassword("pwdFile");
           if (signStore.exists()) {
               password = "changeit";
               store = KeyStoreTool
                       .loadStore(new FileInputStream(signStore), "changeit".toCharArray(), "PKCS12");
               Enumeration<String> aliases = store.aliases();
               if (aliases.hasMoreElements()) {
                   foundID = aliases.nextElement();
                   found = true;
               }
           } else {
               File keyFile = new File(APP_DIR_TRUST, "privKeystore" + ".p12");
               Logger.trace("CRL list file is: " + keyFile.getAbsolutePath());

               store = KeyStoreTool
                       .loadStore(new FileInputStream(keyFile), password.toCharArray(), "PKCS12");
               Enumeration<String> aliases = store.aliases();
               while (aliases.hasMoreElements() && !found) {
                   String alias = aliases.nextElement();
                   if (alias.contains("User")) {
                       Logger.trace("Alias found is:" + alias);
                       found = true;
                       foundID = alias;
                   }
               }
           }
           if (found) {
               Logger.trace("Read keys");
               Tuple<PrivateKey, X509Certificate[]> keys =
                       KeyStoreTool.getKeyEntry(store, foundID, password.toCharArray());
               CertWriterReader.KeyStoreBean bean =
                       new CertWriterReader.KeyStoreBean(keys.getSecond(), keys.getFirst());
               Logger.trace("Before signing with:" + sigType + " and " + smode.getMode());
               Part part = servletRequest.getPart("data_to_sign");
               File tempData =File.createTempFile("data", ".dat");
               FileOutputStream tempOut = new FileOutputStream(tempData);
               IOUtils.copy(part.getInputStream(), tempOut);
               tempOut.close();
               SigningBean signingBean = new SigningBean()
                       .setDataIN(part.getInputStream())
                       .setDataINFile(tempData)
                       .setDigestAlgorithm(DigestAlg.getFromName(digestAlg))
                       .setSignatureAlgorithm(SignatureAlg.getFromName(sigAlg))
                       .setSigningMode(smode)
                       .setKeyStoreBean(bean)
                       .setAttributeCertificate(attrCert);
               SigningUtil util = new SigningUtil();
               DataSource ds = null;
               if (sigType.equals(SigningBean.SigningType.CMS.name())) {
                   Logger.trace("Sign CMS");
                   ds = util.signCMS(signingBean);
                   IOUtils.copy(ds.getInputStream(), servletResponse.getOutputStream());
                   servletResponse.setStatus(Response.Status.CREATED.getStatusCode());
                   Logger.trace("Signed CMS");
               } else if(sigType.equals(SigningBean.SigningType.CAdES.name())) {
                   Logger.trace("Sign CAdES");
                   String url = null;
                   boolean setArchiveInfo = false;
                   if (jInput.signing.cadesParams != null) {
                       url = jInput.signing.cadesParams.TSAURL;
                       setArchiveInfo = jInput.signing.cadesParams.addArchiveinfo;
                   }
                   signingBean = signingBean.setTspURL(url);
                   ds = util.signCAdES(signingBean, setArchiveInfo);
                   InputStream input = ds.getInputStream();
                   OutputStream servletOut = servletResponse.getOutputStream();
                   IOUtils.copy(input, servletOut);
                   servletOut.flush();
                   servletOut.close();
                   input.close();
                   servletResponse.setStatus(Response.Status.CREATED.getStatusCode());
                   Logger.trace("Http Status is: " + servletResponse.getStatus());
                   Logger.trace("Signed CAdES");
                   Thread.sleep(10 * 1000);
                   Logger.trace(" Now return");
               } else if(sigType.equals(SigningBean.SigningType.PAdES.name())) {
                   Logger.trace("Sign PAdES");
                   tempData.delete();
                   signingBean = signingBean.setOutputPath(tempData.getAbsolutePath());
                   String url = null;
                   if (jInput.signing.cadesParams != null) {
                       url = jInput.signing.cadesParams.TSAURL;
                   }
                   signingBean = signingBean.setTspURL(url);
                   SignPDFUtil pdfutil = new SignPDFUtil(bean.getSelectedKey(), bean.getChain());
                   Logger.trace("Build signing parameters");
                   PadesBESParameters params = pdfutil.createParameters(signingBean);
                   Logger.trace("Prepare signing");
                   Logger.trace("Really sign");
                   pdfutil.signPDF(signingBean,  params, "IAIK");
                   IOUtils.copy(new FileInputStream(tempData), servletResponse.getOutputStream());
                   Logger.trace("Signed PAdES");
                   servletResponse.setStatus(Response.Status.CREATED.getStatusCode());
               }
           } else {
               servletResponse.setStatus(Response.Status.BAD_REQUEST.getStatusCode());
           }
       } catch (Exception ex) {
           Logger.trace("error during document signing " + ex.getMessage());
           Logger.trace(ex);
       }
    }

    private void docCompress(HttpServletRequest servletRequest, HttpServletResponse servletResponse, GSON.Params jInput) throws KeyStoreException, IOException, ServletException {
        try {
            Logger.trace("read params....");
            String sigType = jInput.signing.signatureType;
            Logger.trace("type is: " + sigType);
            String sigAlg = jInput.signing.signatureAlgorithm;
            String digestAlg = jInput.signing.digestAlgorithm;
            SigningBean.Mode smode;
            File signStore = new File(APP_DIR, PROP_SIGNSTORE);
            boolean found = false;
            String foundID = null;
            KeyStore store = null;
            String password = decryptPassword("pwdFile");

            if(sigType.equals(SigningBean.SigningType.Compress.name())) {
                Logger.trace("Compress data");
                Part part = servletRequest.getPart("data_to_sign");
                SigningBean signingBean = new SigningBean().setDataIN(part.getInputStream());
                DataSource result = CMSCompressUtil.compressDataStreamCMS(signingBean);
                Logger.trace("Data compressed");
                IOUtils.copy(result.getInputStream(), servletResponse.getOutputStream());
                servletResponse.setStatus(Response.Status.CREATED.getStatusCode());
            } else if(sigType.equals(SigningBean.SigningType.Compress.name())) {
                Logger.trace("DeCompress data");
                Part part = servletRequest.getPart("data_to_sign");
                SigningBean signingBean = new SigningBean().setDataIN(part.getInputStream());
                DataSource result = CMSCompressUtil.decompressDataStreamCMS(signingBean);
                Logger.trace("Data de-compressed");
                IOUtils.copy(result.getInputStream(), servletResponse.getOutputStream());
                servletResponse.setStatus(Response.Status.CREATED.getStatusCode());
            } else {
                servletResponse.setStatus(Response.Status.BAD_REQUEST.getStatusCode());
            }
        } catch (Exception ex) {
            Logger.trace("error during document signing " + ex.getMessage());
            Logger.trace(ex);
        }
    }

    private void docVerify(HttpServletRequest servletRequest, HttpServletResponse servletResponse, GSON.Params jInput) throws KeyStoreException, IOException, ServletException {
        try {
            Logger.trace("read params....");
            String sigType = jInput.signing.signatureType;
            Logger.trace("type is: " + sigType);
            String sigAlg = jInput.signing.signatureAlgorithm;
            String digestAlg = jInput.signing.digestAlgorithm;
            SigningBean.Mode smode;
            File signStore = new File(APP_DIR, PROP_SIGNSTORE);
            boolean found = false;
            String foundID = null;
            KeyStore store = null;
            String password = decryptPassword("pwdFile");

            if(sigType.equals(SigningBean.SigningType.Compress.name())) {
                Logger.trace("Compress data");
                Part part = servletRequest.getPart("data_to_sign");
                SigningBean signingBean = new SigningBean().setDataIN(part.getInputStream());
                DataSource result = CMSCompressUtil.compressDataStreamCMS(signingBean);
                Logger.trace("Data compressed");
                IOUtils.copy(result.getInputStream(), servletResponse.getOutputStream());
                servletResponse.setStatus(Response.Status.CREATED.getStatusCode());
            } else if(sigType.equals(SigningBean.SigningType.Compress.name())) {
                Logger.trace("DeCompress data");
                Part part = servletRequest.getPart("data_to_sign");
                SigningBean signingBean = new SigningBean().setDataIN(part.getInputStream());
                DataSource result = CMSCompressUtil.decompressDataStreamCMS(signingBean);
                Logger.trace("Data de-compressed");
                IOUtils.copy(result.getInputStream(), servletResponse.getOutputStream());
                servletResponse.setStatus(Response.Status.CREATED.getStatusCode());
            } else {
                servletResponse.setStatus(Response.Status.BAD_REQUEST.getStatusCode());
            }
        } catch (Exception ex) {
            Logger.trace("error during document signing " + ex.getMessage());
            Logger.trace(ex);
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
