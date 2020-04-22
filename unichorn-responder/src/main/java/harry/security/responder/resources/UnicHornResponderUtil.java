package harry.security.responder.resources;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.IssuerAndSerialNumber;
import iaik.utils.ASN1InputStream;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.*;
import iaik.x509.ocsp.utils.ResponseGenerator;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.KeyStoreTool;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

public class UnicHornResponderUtil {

    public static OCSPResponse generateResponse(OCSPRequest ocspRequest,
                                                InputStream ocspReqInput,
                                                ResponseGenerator responseGenerator,
                                                AlgorithmID signatureAlgorithm,
                                                Map<String, String> messages) {
        messages.put("beforeks", "before getting keys and certs");
        Tuple<PrivateKey, X509Certificate> keys = null;
        try {
            InputStream keyStore = UnicHornResponderUtil.class.getResourceAsStream("/application.jks");
            KeyStore store = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "JKS");
            keys = KeyStoreTool.getKeyEntry(store, UnichornResponder.ALIAS, "geheim".toCharArray());
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
                signatureAlgorithm = AlgorithmID.dsaWithSHA3_256;
            } else {
                signatureAlgorithm = AlgorithmID.sha256WithRSAEncryption;
            }
        }
        try {
            messages.put("info-1", "Message is:" + signatureAlgorithm.getImplementationName());
        } catch (Exception ex){

        }
        // read crl

        X509CRL crl = readCrl(UnicHornResponderUtil.class.getResourceAsStream("/unichorn.crl"));
        messages.put("info-2", "Message is: crl loaded" );
        System.out.println("Create response entries for crl...");
        X509Certificate crlIssuer = keys.getSecond();
        messages.put("info-3", "Message is: before add resp entries" );
        try {
            Request[] requests = ocspRequest.getRequestList();
            for (Request req:requests) {
                Date endDate = getDate("2020-01-01");
                java.util.Date startDate = getDate("2020-01-01");
                ReqCert reqCert = req.getReqCert();
                if (reqCert.getType() == ReqCert.certID){
                    CertID certID = (CertID)reqCert.getReqCert();
                    BigInteger serial = certID.getSerialNumber();

                    if ( !crl.isRevoked(serial)) {
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(), endDate, null);
                    } else {
                        RevokedInfo info = new RevokedInfo(startDate);
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(info), endDate, null);
                    }

                } else if (reqCert.getType() == ReqCert.issuerSerial){
                    IssuerAndSerialNumber number = (IssuerAndSerialNumber)reqCert.getReqCert();

                    if ( !crl.isRevoked(number.getSerialNumber())) {
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(), endDate, null);
                    } else {
                        RevokedInfo info = new RevokedInfo(startDate);
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(info),endDate, null);
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
            messages.put("beforecrea", "before create response internal");// changed public key setting
            OCSPResponse response = responseGenerator.createOCSPResponse(ocspReqInput,
                    keys.getSecond().getPublicKey(), signatureAlgorithm, null);
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

    private static java.util.Date getDate(String newDate) {
        SimpleDateFormat textFormat = new SimpleDateFormat("yyyy-MM-dd");
        String paramDateAsString = newDate;
        java.util.Date myDate = null;

        try {
            myDate = textFormat.parse(paramDateAsString);
            return myDate;
        } catch(Exception ex) {
            return null;
        }
    }

}
