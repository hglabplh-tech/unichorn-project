package harry.security.responder.resources;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.SecurityProvider;
import iaik.cms.ecc.ECCelerateProvider;
import iaik.security.ec.provider.ECCelerate;
import iaik.security.provider.IAIKMD;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.OCSPRequest;
import iaik.x509.ocsp.OCSPResponse;
import iaik.x509.ocsp.utils.ResponseGenerator;
import org.apache.commons.io.IOUtils;
import org.harry.security.util.SigningUtil;
import org.harry.security.util.Tuple;
import org.harry.security.util.algoritms.DigestAlg;
import org.harry.security.util.algoritms.SignatureAlg;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.pmw.tinylog.Configurator;
import org.pmw.tinylog.Level;
import org.pmw.tinylog.Logger;
import org.pmw.tinylog.writers.FileWriter;

import javax.activation.DataSource;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;
import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.*;

import static harry.security.responder.resources.UnicHornResponderUtil.*;

@WebServlet
public class SigningResponder extends HttpServlet {



    public static final String ALIAS = "b998b1f7-04fe-42c6-8284-9fb21e604b60UserRSA";



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
        Map<String,String> messages = new HashMap<>();
        messages.put("pre", "pre started: ");
        try {
            String sigType = servletRequest.getHeader("signatureType");
            String mode = servletRequest.getHeader("mode");
            SigningBean.Mode smode;
            if (mode.equals("explicit")) {
                smode = SigningBean.Mode.EXPLICIT;
            } else {
                smode = SigningBean.Mode.IMPLICIT;
            }
            File keyFile = new File(UnicHornResponderUtil.APP_DIR_TRUST, "privKeystore" + ".p12");
            Logger.trace("CRL list file is: " + keyFile.getAbsolutePath());
            String password = decryptPassword("pwdFile");
            KeyStore store = KeyStoreTool
                    .loadStore(new FileInputStream(keyFile), password.toCharArray(),"PKCS12");
            Enumeration<String> aliases = store.aliases();
            boolean found = false;
            String foundID = null;
            while (aliases.hasMoreElements() && !found) {
                String alias = aliases.nextElement();
                if (alias.contains("user")) {
                    Logger.trace("Alias found is:" + alias);
                    found = true;
                    foundID = alias;
                }
            }
            if (found) {
                Logger.trace("Read keys");
                Tuple<PrivateKey, X509Certificate[]> keys =
                        KeyStoreTool.getKeyEntry(store, foundID, password.toCharArray());
                CertWriterReader.KeyStoreBean bean=
                        new CertWriterReader.KeyStoreBean(keys.getSecond(), keys.getFirst());
                Logger.trace("Before signing with:" + sigType + " and " + smode.getMode());
                SigningBean signingBean = new SigningBean()
                        .setDataIN(servletRequest.getInputStream())
                        .setSigningMode(smode)
                        .setKeyStoreBean(bean);
                SigningUtil util = new SigningUtil();
                DataSource ds = null;
                if (sigType.equals("CMS")) {
                    Logger.trace("Sign CMS");
                    ds =util.signCMS(signingBean);
                    IOUtils.copy(ds.getInputStream(), servletResponse.getOutputStream());
                    servletResponse.setStatus(Response.Status.CREATED.getStatusCode());
                    Logger.trace("Signed CMS");
                } else {
                    Logger.trace("Sign CAdES");
                    ds =util.signCAdES(signingBean, false);
                    IOUtils.copy(ds.getInputStream(), servletResponse.getOutputStream());
                    servletResponse.setStatus(Response.Status.CREATED.getStatusCode());
                    Logger.trace("Signed CAdES");
                }
            }  else {
                servletResponse.setStatus(Response.Status.BAD_REQUEST.getStatusCode());
            }

        } catch (Exception ex) {
            servletResponse.setStatus(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
            Logger.trace("Error Message is:" + ex.getMessage());
            for(String key: messages.keySet()) {
                servletResponse.addHeader(key, messages.get(key));
            }
        }



    }


}
