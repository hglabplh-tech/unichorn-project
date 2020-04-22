package harry.security.responder.resources;

import iaik.asn1.CodingException;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.cms.IssuerAndSerialNumber;
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
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.sql.Date;
import java.util.HashMap;
import java.util.Map;

import static iaik.x509.ocsp.CertStatus.*;
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

            OCSPResponse response = generateResponse(ocspRequest, messages);
            Logger.debug("Write stream");
            response.writeTo(servletResponse.getOutputStream());
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

    public OCSPResponse generateResponse(OCSPRequest ocspRequest, Map<String, String> messages) {
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
            signatureAlgorithm = AlgorithmID.sha256WithRSAEncryption;

        } catch (Exception ex){
            messages.put("keysexcp", "IO keystore exception" + ex.getMessage() + " of Type: " + ex.getClass().getName());
        }
        //
        PrivateKey responderKey = responseGenerator.getResponderKey();

        if (!(responderKey instanceof java.security.interfaces.RSAPrivateKey)) {
            if (responderKey instanceof java.security.interfaces.DSAPrivateKey) {
                signatureAlgorithm = AlgorithmID.dsa;
            } else {
                signatureAlgorithm = AlgorithmID.sha256WithRSAEncryption;
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
            Request[] requests = ocspRequest.getRequestList();
            for (Request req:requests) {
                ReqCert reqCert = req.getReqCert();
                if (reqCert.getType() == ReqCert.certID){
                    CertID certID = (CertID)reqCert.getReqCert();
                    BigInteger serial = certID.getSerialNumber();
                    if ( !crl.isRevoked(serial)) {
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(), Date.valueOf("2024.01.01"), null);
                    } else {
                        RevokedInfo info = new RevokedInfo(Date.valueOf("2020.01.01"));
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(info),Date.valueOf("2024.01.01"), null);
                    }

                } else if (reqCert.getType() == ReqCert.issuerSerial){
                    IssuerAndSerialNumber number = (IssuerAndSerialNumber)reqCert.getReqCert();

                    if ( !crl.isRevoked(number.getSerialNumber())) {
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(), Date.valueOf("2024.01.01"), null);
                    } else {
                        RevokedInfo info = new RevokedInfo(Date.valueOf("2020.01.01"));
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(info),Date.valueOf("2024.01.01"), null);
                    }
                } else if (reqCert.getType() == ReqCert.pKCert){
                    X509Certificate certificate = (X509Certificate)reqCert.getReqCert();
                    if (!crl.isRevoked(certificate)) {
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(), certificate.getNotAfter(), null);
                    } else {
                        RevokedInfo info = new RevokedInfo(certificate.getNotAfter());
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(info), certificate.getNotAfter(), null);
                    }
                }
            }
           // responseGenerator.addResponseEntries(crl, crlIssuer, ReqCert.certID);
            messages.put("info-4", "Message is: generator created");
            System.out.println("Generator created:");
            System.out.println(responseGenerator);
        } catch (Exception ex) {
            messages.put("err-gen", "Message is: generator is NOT created due to: " + ex.getMessage());
        }


        try {
            messages.put("beforecrea", "before create response internal");
            OCSPResponse response = responseGenerator.createOCSPResponse(new ByteArrayInputStream(ocspRequest.getEncoded()),
                    null, signatureAlgorithm, null);
            messages.put("aftercrea", "after create internal");
            messages.put("info-5", "Message is: output ok");
            return response;
        } catch (Exception ex) {
            messages.put("info-4", "Message is: try to output failed with: " + ex.getMessage());
            throw new IllegalStateException("response was not generated ", ex);
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
