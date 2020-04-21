package harry.security.responder.resources;

import iaik.asn1.CodingException;
import iaik.asn1.structures.AlgorithmID;
import iaik.utils.ASN1InputStream;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.*;
import iaik.x509.ocsp.extensions.CrlID;
import iaik.x509.ocsp.utils.ResponseGenerator;
import org.harry.security.util.ConfigReader;
import org.harry.security.util.SigningUtil;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.tinylog.Logger;


import javax.servlet.*;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

import static org.harry.security.util.certandkey.CertWriterReader.loadSecrets;


public class UnichornResponder extends HttpServlet {

    

    private static final String ALIAS = "Common T-Systems Green TeamUserRSA";
    /**
     * Use an OCSP ResponseGenerator for request parsing / response generation.
     */
    private ResponseGenerator responseGenerator;
    /**
     * Algorithm to be used for signing the response.
	 */
    private AlgorithmID signatureAlgorithm = AlgorithmID.rsa;

    @Override
    public void doPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws ServletException, IOException {
        String output = "Jersey say : ";
        System.out.println("Hallo here I am");
        Logger.debug("enter ocsp method");
        Map<String,String> messages = new HashMap<>();
        messages.put("pre", "pre started: ");
        try {
            InputStream stream = servletRequest.getInputStream();
            String indicator = (stream == null) ? "null" : "not null";
            messages.put("info-pre", "pre request read stream is: " + indicator);
            OCSPRequest ocspRequest = new OCSPRequest(stream);

            messages.put("info-pre2", "request read");

            OCSPResponse ocspResp = generateResponse(ocspRequest, messages);
            Logger.debug("end generating response");
            ocspResp.writeTo(servletResponse.getOutputStream());
            Logger.debug("written stream");
            servletResponse.setStatus(200);
        } catch (Exception ex) {
            servletResponse.setStatus(400);
            servletResponse.setHeader("error", "Message is:" + ex.getMessage());
            for(String key: messages.keySet()) {
                servletResponse.addHeader(key, messages.get(key));
            }
        }



    }

    public OCSPResponse generateResponse(OCSPRequest ocspRequest, Map<String, String> messages) throws OCSPException, SignatureException, IOException, CertificateException, CodingException {
        messages.put("beforeks", "before getting keys and certs");
        Tuple<PrivateKey, X509Certificate> keys = null;
        try {
            InputStream keyStore = UnichornResponder.class.getResourceAsStream("/application.jks");
            KeyStore store = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "JKS");
            keys = KeyStoreTool.getKeyEntry(store, ALIAS, "geheim".toCharArray());
            messages.put("afterks", "after getting keys and certs");
            X509Certificate[] certs = new X509Certificate[1];
            certs[0] = keys.getSecond();
            messages.put("beforegen", "before getting keystoregen");
            responseGenerator = new ResponseGenerator(keys.getFirst(), certs);
            messages.put("aftergen", "after getting keystoregen");
            signatureAlgorithm = AlgorithmID.sha1WithRSAEncryption;
            messages.put("beforecrea", "before create response internal");
            responseGenerator.createOCSPResponse(new ByteArrayInputStream(ocspRequest.getEncoded()),
                    null, signatureAlgorithm, null);
            messages.put("aftercrea", "after create internal");
        } catch (Exception ex){
            messages.put("keysexcp", "IO keystore exception" + ex.getMessage() + " of Type: " + ex.getClass().getName());
        }
        //
        PrivateKey responderKey = responseGenerator.getResponderKey();

        if (!(responderKey instanceof java.security.interfaces.RSAPrivateKey)) {
            if (responderKey instanceof java.security.interfaces.DSAPrivateKey) {
                signatureAlgorithm = AlgorithmID.dsa;
            } else {
                signatureAlgorithm = AlgorithmID.rsa;
            }
        }
        try {
            messages.put("info-1", "Message is:" + signatureAlgorithm.getImplementationName());
        } catch (Exception ex){

        }
        // read crl

        X509CRL crl = readCrl(UnichornResponder.class.getResourceAsStream("/unichorn.crl"));
        messages.put("info-2", "Message is: crl loaded" );
        System.out.println("Create response entries for crl...");
        X509Certificate crlIssuer = keys.getSecond();
        messages.put("info-3", "Message is: before add resp entries" );
        try {
            responseGenerator.addResponseEntries(crl, crlIssuer, ReqCert.certID);
            messages.put("info-4", "Message is: generator created");
            System.out.println("Generator created:");
            System.out.println(responseGenerator);
        } catch (Exception ex) {
            messages.put("err-gen", "Message is: generator is NOT created due to: " + ex.getMessage());
        }

        ByteArrayOutputStream os = null;
        try {
            os = new ByteArrayOutputStream();
            responseGenerator.writeTo(os);
            OCSPResponse response = new OCSPResponse(new ByteArrayInputStream(os.toByteArray()));
            return response;
        } catch (Exception ex) {
            throw new IllegalStateException("response was not generated ", ex);
        } finally {
            if (os != null) {
                try {
                    os.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        }
    }

    /**
     * Reads a X.509 crl from the given file.
     *
     * @param is
     *          the name of the crl file
     * @return the crl
     */
    private static X509CRL readCrl(InputStream is) {

        X509CRL crl = null;
        try {
            crl = new X509CRL(new ASN1InputStream(is));
        } catch (Exception ex) {
            ex.printStackTrace();
            System.exit(-1);
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        }
        return crl;
    }




}
