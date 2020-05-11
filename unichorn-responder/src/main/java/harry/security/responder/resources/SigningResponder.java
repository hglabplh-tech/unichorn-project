package harry.security.responder.resources;

import com.google.gson.Gson;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.cms.SignedData;
import iaik.pkcs.pkcs10.CertificateRequest;
import iaik.pkcs.pkcs8.EncryptedPrivateKeyInfo;
import iaik.pkcs.pkcs9.ChallengePassword;
import iaik.pkcs.pkcs9.ExtensionRequest;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.KeyUsage;
import iaik.x509.extensions.SubjectKeyIdentifier;
import iaik.x509.ocsp.utils.ResponseGenerator;
import org.apache.commons.io.IOUtils;
import org.harry.security.util.CertificateWizzard;
import org.harry.security.util.SigningUtil;
import org.harry.security.util.Tuple;
import org.harry.security.util.algoritms.DigestAlg;
import org.harry.security.util.algoritms.SignatureAlg;
import org.harry.security.util.bean.SigningBean;
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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

import static harry.security.responder.resources.UnicHornResponderUtil.*;
import static org.harry.security.util.CertificateWizzard.PROP_STORE_NAME;
import static org.harry.security.util.CertificateWizzard.PROP_TRUST_NAME;

@WebServlet
@MultipartConfig(
        location = "c:\\tmp",
        fileSizeThreshold   = 1024 * 1024 * 10,  // 10 MB
        maxFileSize         = 1024 * 1024 * 100, // 100 MB
        maxRequestSize      = 1024 * 1024 * 150 // 150 MB
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
    public void doPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws ServletException, IOException {
       init ();
        String output = "Jersey say : ";
        Logger.trace("Hallo here I am");
        Logger.trace("enter ocsp method");




   try {
       GSON.Params jInput = readJSon(servletRequest);
       if (jInput.parmType.equals("docSign")) {
           docSigning(servletRequest, servletResponse, jInput);
       } else if (jInput.parmType.equals("certSign")) {
           certSigning(servletRequest, servletResponse, jInput);
       } else if (jInput.parmType.equals("saveProps")) {
           saveAppProperties(servletRequest, servletResponse, jInput);
       } else if(jInput.parmType.equals("initKeys")) {
           File keystore = new File(APP_DIR, PROP_STORE_NAME);
           File keystoreEC = new File(APP_DIR, PROP_STORE_NAME + "_EC");
           File trustFile = new File(APP_DIR_TRUST, PROP_TRUST_NAME);
           keystore.delete();
           keystoreEC.delete();
           trustFile.delete();
           CertificateWizzard.initThis();
       } else if(jInput.parmType.equals("setSigningStore")) {
           saveSignKeyStore(servletRequest, servletResponse, jInput);
        } else if(jInput.parmType.equals("resignCRL")) {
           resignCRL(servletResponse);
       }
        } catch (Exception ex) {
            servletResponse.setStatus(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
            Logger.trace("Error Message is:" + ex.getMessage());
           Logger.trace(ex);
        }





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
        }if (action != null & action.equals("clean")) {

        }
    }

    private void certSigning(HttpServletRequest servletRequest, HttpServletResponse servletResponse, GSON.Params jInput) throws KeyStoreException, IOException, ServletException {
       try {
           Part part = servletRequest.getPart("data_to_sign");
           CertificateRequest certReq = new CertificateRequest(part.getInputStream());
           PublicKey pubKey = certReq.getPublicKey();
           Name subject = certReq.getSubject();
           KeyStore store = KeyStoreTool.loadAppStore();
           Enumeration<String> aliases = store.aliases();
           Tuple<PrivateKey, X509Certificate[]> keys = null;
           while(aliases.hasMoreElements()) {
               String alias = aliases.nextElement();
               if (alias.contains("Intermediate")) {
                   keys =
                           KeyStoreTool.getKeyEntry(store,alias, "geheim".toCharArray());
                   Logger.trace("Keys found for alias: " + alias);
               }
           }
           if (keys != null) {
               // look for a ChallengePassword attribute
               ChallengePassword challengePassword = (ChallengePassword) certReq
                       .getAttributeValue(ChallengePassword.oid);
               if (challengePassword != null) {
                   System.out.println("Certificate request contains a challenge password: \""
                           + challengePassword.getPassword() + "\".");
               }
               PrivateKey userKey = null;
               X509Certificate userCert = null;
               Logger.trace("Check challenge password: " + challengePassword.getPassword());
               File pwdFile = new File(APP_DIR_WORKING, challengePassword.getPassword());
               if (!pwdFile.exists()) {
                   Logger.trace("Check challenge password failed");
                   servletResponse.setStatus(Response.Status.FORBIDDEN.getStatusCode());
                   return;
               } else {
                   Logger.trace("Check challenge password success");
                   Part info = servletRequest.getPart("info");
                   if (info != null) {
                       Logger.trace("Read private key encrypted");
                       InputStream infoStream = info.getInputStream();
                       ByteArrayOutputStream infoOut = new ByteArrayOutputStream();
                       IOUtils.copy(infoStream, infoOut);
                       // decode, decrypt, unwrap
                       EncryptedPrivateKeyInfo epki =
                               new EncryptedPrivateKeyInfo(infoOut.toByteArray());

                       userKey = epki.decrypt(challengePassword.getPassword());
                       Logger.trace("private key decrypted success");
                   }
                   pwdFile.delete();
               }
               Logger.trace("Create certificate");
               Name issuer = (Name)keys.getSecond()[0].getSubjectDN();
               ExtensionRequest extensionRequest = (ExtensionRequest) certReq
                       .getAttributeValue(ExtensionRequest.oid);
               if (extensionRequest != null) {
                   // we know that KeyUsage is included
                   KeyUsage keyUsage = (KeyUsage) extensionRequest.getExtension(KeyUsage.oid);
                   SubjectKeyIdentifier subjectKeyID = new SubjectKeyIdentifier(keys.getSecond()[0].getPublicKey());
                   userCert = CertificateWizzard.createCertificate(subject,
                           pubKey, issuer,
                           keys.getFirst(), AlgorithmID.sha256WithRSAEncryption,
                           subjectKeyID.get(),
                           keyUsage);
                   Logger.trace("Create certificate success");
               }
               if (userKey != null && userCert != null) {
                   Logger.trace("Add key to trusted");
                   X509Certificate[] chain = new X509Certificate[3];
                   chain[2] = keys.getSecond()[1];
                   chain[1] = keys.getSecond()[0];
                   chain[0] = userCert;
                   File keyFile = new File(UnicHornResponderUtil.APP_DIR_TRUST, "privKeystore" + ".p12");
                   File tempKeyFile = File.createTempFile("keystore", ".p12");
                   tempKeyFile.delete();
                   String passwd = decryptPassword("pwdFile");
                   applyKeyStore(keyFile, userKey,
                           chain,
                           passwd, "PKCS12");
                   applyKeyStore(tempKeyFile, userKey,
                           chain,
                           "changeit", "PKCS12");
                   FileInputStream keyStore = new FileInputStream(tempKeyFile);
                   IOUtils.copy(keyStore, servletResponse.getOutputStream());
                   servletResponse.setStatus(Response.Status.CREATED.getStatusCode());
                   Logger.trace("Add key to trusted success");
               }
           }
       } catch (Exception ex) {
           Logger.trace("error during cedrtificate signing");
           Logger.trace(ex);
           throw new IllegalStateException(
                   "error during cedrtificate signing", ex);
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
               File keyFile = new File(UnicHornResponderUtil.APP_DIR_TRUST, "privKeystore" + ".p12");
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
               SigningBean signingBean = new SigningBean()
                       .setDataIN(part.getInputStream())
                       .setDigestAlgorithm(DigestAlg.getFromName(digestAlg))
                       .setSignatureAlgorithm(SignatureAlg.getFromName(sigAlg))
                       .setSigningMode(smode)
                       .setKeyStoreBean(bean);
               SigningUtil util = new SigningUtil();
               DataSource ds = null;
               if (sigType.equals("CMS")) {
                   Logger.trace("Sign CMS");
                   ds = util.signCMS(signingBean);
                   IOUtils.copy(ds.getInputStream(), servletResponse.getOutputStream());
                   servletResponse.setStatus(Response.Status.CREATED.getStatusCode());
                   Logger.trace("Signed CMS");
               } else {
                   Logger.trace("Sign CAdES");
                   String url = null;
                   boolean setArchiveInfo = false;
                   if (jInput.signing.cadesParams != null) {
                       url = jInput.signing.cadesParams.TSAURL;
                       setArchiveInfo = jInput.signing.cadesParams.addArchiveinfo;
                   }
                   signingBean = signingBean.setTspURL(url);
                   ds = util.signCAdES(signingBean, setArchiveInfo);
                   IOUtils.copy(ds.getInputStream(), servletResponse.getOutputStream());
                   servletResponse.setStatus(Response.Status.CREATED.getStatusCode());
                   Logger.trace("Signed CAdES");
               }
           } else {
               servletResponse.setStatus(Response.Status.BAD_REQUEST.getStatusCode());
           }
       } catch (Exception ex) {
           Logger.trace("error during document signing " + ex.getMessage());
           Logger.trace(ex);
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
