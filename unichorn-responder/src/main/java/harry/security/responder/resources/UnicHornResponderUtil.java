package harry.security.responder.resources;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.IssuerAndSerialNumber;
import iaik.utils.ASN1InputStream;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.ReasonCode;
import iaik.x509.ocsp.*;
import iaik.x509.ocsp.utils.ResponseGenerator;
import org.apache.tools.ant.types.selectors.ReadableSelector;
import org.apache.tools.ant.util.LeadPipeInputStream;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.KeyStoreTool;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CRLReason;
import java.security.cert.X509CRLEntry;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.harry.security.util.ocsp.HttpOCSPClient.getCRLOfCert;

public class UnicHornResponderUtil {

    public static String APP_DIR;

    public  static String APP_DIR_TRUST;

    static {
        String userDir = System.getProperty("user.home");
        userDir = userDir + "\\AppData\\Local\\MySigningApp";
        File dir = new File(userDir);
        if (!dir.exists()){
            dir.mkdirs();
        }
        File dirTrust = new File(userDir, "trustedLists");
        if (!dirTrust.exists()) {
            dirTrust.mkdirs();
        }
        UnicHornResponderUtil.APP_DIR_TRUST = dirTrust.getAbsolutePath();
        UnicHornResponderUtil.APP_DIR = userDir;
    }

    public static OCSPResponse generateResponse(OCSPRequest ocspRequest,
                                                InputStream ocspReqInput,
                                                ResponseGenerator responseGenerator,
                                                AlgorithmID signatureAlgorithm,
                                                Map<String, String> messages) {
        messages.put("beforeks", "before getting keys and certs");
        Tuple<PrivateKey, X509Certificate[]> keys = null;
        try {
            checkRequestSigning(ocspRequest);
            messages.put("afterks", "after getting keys and certs");
            keys = getPrivateKeyX509CertificateTuple();
            X509Certificate[] certs = new X509Certificate[1];
            certs = keys.getSecond();

            messages.put("beforegen", "before getting keystoregen");
            responseGenerator = new ResponseGenerator(keys.getFirst(), certs);
            messages.put("aftergen", "after getting keystoregen");
            signatureAlgorithm = AlgorithmID.sha256WithRSAEncryption;


        } catch (Exception ex){
            messages.put("keysexcp", "IO keystore exception" + ex.getMessage() + " of Type: " + ex.getClass().getName());
        }
        //
        PrivateKey responderKey = responseGenerator.getResponderKey();

        signatureAlgorithm = getAlgorithmID(signatureAlgorithm, messages, responderKey);
        // read crl

        X509CRL crl = readCrl(UnicHornResponderUtil.class.getResourceAsStream("/unichorn.crl"));
        List<X509CRL> crlList = new ArrayList<>();
        crlList.add(crl);
        crlList.addAll(getMoreCRLs());
        messages.put("info-2", "Message is: crl loaded" );
        System.out.println("Create response entries for crl...");

        messages.put("info-3", "Message is: before add resp entries" );
        checkCertificateRevocation(ocspRequest, responseGenerator, messages, crl);


        try {
            return getOcspResponse(ocspReqInput, responseGenerator, signatureAlgorithm, messages, keys);
        } catch (Exception ex) {
            messages.put("info-4", "Message is: try to output failed with: " + ex.getMessage());
            throw new IllegalStateException("response was not generated ", ex);
        }
    }

    private static OCSPResponse getOcspResponse(InputStream ocspReqInput, ResponseGenerator responseGenerator, AlgorithmID signatureAlgorithm, Map<String, String> messages, Tuple<PrivateKey, X509Certificate[]> keys) {
        messages.put("beforecrea", "before create response internal");// changed public key setting
        OCSPResponse response = responseGenerator.createOCSPResponse(ocspReqInput,
                keys.getSecond()[0].getPublicKey(), signatureAlgorithm, null);
        messages.put("aftercrea", "after create internal");
        messages.put("info-5", "Message is: output ok");
        return response;
    }

    private static void checkCertificateRevocation(OCSPRequest ocspRequest, ResponseGenerator responseGenerator, Map<String, String> messages, X509CRL crl) {
        try {
            Request[] requests = ocspRequest.getRequestList();
            for (Request req:requests) {
                Date endDate = getDate("2020-01-01");
                Date startDate = getDate("2020-01-01");
                ReqCert reqCert = req.getReqCert();
                if (reqCert.getType() == ReqCert.certID){
                    CertID certID = (CertID)reqCert.getReqCert();
                    BigInteger serial = certID.getSerialNumber();

                    if ( !crl.isRevoked(serial)) {
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(), endDate, null);
                    } else {
                        X509CRLEntry entry = crl.getRevokedCertificate(serial);
                        CRLReason reason = entry.getRevocationReason();
                        RevokedInfo info = new RevokedInfo(startDate);
                        info.setRevocationReason(translateRevocationReason(reason));
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(info), endDate, null);
                    }

                } else if (reqCert.getType() == ReqCert.issuerSerial){
                    IssuerAndSerialNumber number = (IssuerAndSerialNumber)reqCert.getReqCert();

                    if ( !crl.isRevoked(number.getSerialNumber())) {
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(), endDate, null);
                    } else {
                        X509CRLEntry entry = crl.getRevokedCertificate(number.getSerialNumber());
                        CRLReason reason = entry.getRevocationReason();
                        RevokedInfo info = new RevokedInfo(startDate);
                        info.setRevocationReason(translateRevocationReason(reason));
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(info),endDate, null);
                    }
                } else if (reqCert.getType() == ReqCert.pKCert){
                    X509Certificate certificate = (X509Certificate)reqCert.getReqCert();
                    X509CRL crlToUse = null;
                    crlToUse = getCRLOfCert(certificate);
                    if (crlToUse == null) {
                        crlToUse = crl;
                    }
                    if (!crlToUse.isRevoked(certificate)) {
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(), certificate.getNotAfter(), null);
                    } else {
                        X509CRLEntry entry = crl.getRevokedCertificate(certificate.getSerialNumber());
                        CRLReason reason = entry.getRevocationReason();
                        RevokedInfo info = new RevokedInfo(certificate.getNotAfter());
                        info.setRevocationReason(translateRevocationReason(reason));
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
    }

    private static AlgorithmID getAlgorithmID(AlgorithmID signatureAlgorithm, Map<String, String> messages, PrivateKey responderKey) {
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
        return signatureAlgorithm;
    }

    private static Tuple<PrivateKey, X509Certificate[]> getPrivateKeyX509CertificateTuple() {
        Tuple<PrivateKey, X509Certificate[]> keys = null;
        InputStream keyStore = UnicHornResponderUtil.class.getResourceAsStream("/application.jks");
        KeyStore store = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "JKS");
        keys = KeyStoreTool.getKeyEntry(store, UnichornResponder.ALIAS, "geheim".toCharArray());
        return keys;
    }

    private static void checkRequestSigning(OCSPRequest ocspRequest) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, OCSPException {
        if (ocspRequest.containsSignature()) {
            System.out.println("Request is signed.");

            boolean signatureOk = false;
            if (!signatureOk && ocspRequest.containsCertificates()) {
                System.out.println("Verifying signature with included signer cert...");

                X509Certificate signerCert = ocspRequest.verify();
                System.out.println("Signature ok from request signer " + signerCert.getSubjectDN());
                signatureOk = true;
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

    private static List<X509CRL> getMoreCRLs() {
        List<X509CRL> result = new ArrayList<>();
        File trustDir = new File(APP_DIR_TRUST);
        if (trustDir.exists() && trustDir.isDirectory()) {
            File [] list = trustDir.listFiles();
            for (File file: list) {
                if  (file.getAbsolutePath().contains(".crl")) {
                    try {
                        result.add(readCrl(new FileInputStream(file)));
                    } catch (IOException ex) {
                        throw new IllegalStateException("I/O error CRL", ex);
                    }
                }
            }
            return result;
        }
        return result;
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

    private static ReasonCode translateRevocationReason(CRLReason reason) {
        ReasonCode result;
        switch(reason) {

            case AA_COMPROMISE:
                result = new ReasonCode(ReasonCode.aACompromise);
                break;
            case REMOVE_FROM_CRL:
                result = new ReasonCode(ReasonCode.removeFromCRL);
                break;
            case CA_COMPROMISE:
                result = new ReasonCode(ReasonCode.cACompromise);
                break;
            case CERTIFICATE_HOLD:
                result = new ReasonCode(ReasonCode.certificateHold);
                break;
            case UNSPECIFIED:
                result = new ReasonCode(ReasonCode.unspecified);
                break;
            case SUPERSEDED:
                result = new ReasonCode(ReasonCode.superseded);
                break;
            case UNUSED:
                result = new ReasonCode(ReasonCode.unspecified);
            case KEY_COMPROMISE:
                result = new ReasonCode(ReasonCode.keyCompromise);
            case PRIVILEGE_WITHDRAWN:
                result = new ReasonCode(ReasonCode.privilegeWithdrawn);
            case AFFILIATION_CHANGED:
                result = new ReasonCode(ReasonCode.affiliationChanged);
                break;
            default:
                throw new IllegalArgumentException("invalid revocation reason");
        }
        return result;
    }


}
