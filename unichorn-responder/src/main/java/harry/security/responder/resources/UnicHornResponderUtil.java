// Copyright (C) 2020 Harald Glab-Plhak
// Also (C) IAIK // T-Systems International GmbH for giving many examples in code and documentation
// worked out here
// http://jce.iaik.at
//
// Copyright (C) 2003 Stiftung Secure Information and
//                    Communication Technologies SIC
// Copyright (C) 2020 Harald Glab-Plhak
//
// http://www.sic.st
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.
//
package harry.security.responder.resources;

import iaik.asn1.ASN1Object;
import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AccessDescription;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.utils.ASN1InputStream;
import iaik.x509.*;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.AuthorityInfoAccess;
import iaik.x509.extensions.ReasonCode;
import iaik.x509.ocsp.*;
import iaik.x509.ocsp.extensions.*;
import iaik.x509.ocsp.net.HttpOCSPRequest;
import iaik.x509.ocsp.utils.ResponseGenerator;
import org.harry.security.util.SigningUtil;
import org.harry.security.util.Tuple;
import org.harry.security.util.algoritms.CryptoAlg;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.CertificateChainUtil;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.ocsp.OCSPCRLClient;
import org.harry.security.util.ocsp.PredefinedResponses;
import org.harry.security.util.trustlist.TrustListLoader;
import org.harry.security.util.trustlist.TrustListManager;
import org.pmw.tinylog.Logger;

import javax.activation.DataSource;
import java.io.*;
import java.math.BigInteger;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;

import static org.harry.security.CommonConst.*;
import static org.harry.security.util.CertificateWizzard.isCertificateSelfSigned;
import static org.harry.security.util.ocsp.OCSPCRLClient.getCRLOfCert;

/**
 * This class is designed for generating a OCSP response for a certain certificate given in
 * a OCSPrequest. The cedrtificate and it's issuer is checked and it is also checked against theGIVEN crl's or is
 * redirected for checking to another delegate responder
 * @author Harald Glab-Plhak
 */
public class UnicHornResponderUtil {

    private static SimpleChainVerifier verifier = new SimpleChainVerifier();

    /**
     * Use an OCSP ResponseGenerator for request parsing / response generation.
     */
    private static ResponseGenerator responseGenerator;
    /**
     * Algorithm to be used for signing the response.
     */
    private static AlgorithmID signatureAlgorithm = AlgorithmID.sha1WithRSAEncryption;

    /**
     * Initialize neccessary directories
     */


    /**
     * generate the OCSP response by checking the certificate and its values for
     * being ok
     * @param ocspRequest the OCSP request
     * @param ocspReqInput the request encoded in a input stream
     * @return a valid ocsp-response
     */
    public static OCSPResponse generateResponse(OCSPRequest ocspRequest,
                                                InputStream ocspReqInput) {
        Logger.trace("Enter generateResponse do the real work of responder.......");
        PredefinedResponses.workingData.set(new PredefinedResponses.LocalCache());
        Logger.trace("Setting cache is ok....");
        loadActualPrivStore();
        Logger.trace("Load certificates ok....");
       /* List<X509Certificate> temp = CertificateChainUtil.loadTrustCerts(workingData.get().getCertificateList());
        workingData.get().setCertificateList(temp); */
        try {
            Logger.trace("Before loading prepared....");
            PredefinedResponses.initStorePreparedResponses();
            Logger.trace("loading prepared ok.....");
        } catch (IOException e) {
            Logger.trace(e);
        } catch (ClassNotFoundException e) {
            Logger.trace(e);
        }
        Logger.trace("before getting keys and certs");
        Tuple<PrivateKey, X509Certificate[]> keys = null;
        Nonce nonceExt = null;
        try {
            nonceExt = checkRequestSigning(ocspRequest);
            if (nonceExt == null) {
                return new OCSPResponse(OCSPResponse.malformedRequest);
            }
            Logger.trace( "after getting keys and certs");
            keys = getPrivateKeyX509CertificateTuple();
            X509Certificate[] certs = new X509Certificate[1];
            certs = keys.getSecond();

            Logger.trace( "before getting keystoregen");
            responseGenerator = new ResponseGenerator(keys.getFirst(), certs);
            Logger.trace("after getting keystoregen");
            signatureAlgorithm = AlgorithmID.sha1WithRSAEncryption;


        } catch (Exception ex) {
            OCSPResponse response = new OCSPResponse(OCSPResponse.unauthorized);
            Logger.trace("IO keystore exception" + ex.getMessage() + " of Type: " + ex.getClass().getName());
            return response;
        }
        //
        PrivateKey responderKey = responseGenerator.getResponderKey();

        signatureAlgorithm = getAlgorithmID(signatureAlgorithm, responderKey);
        // read crl

        X509CRL crl = readCrl(loadActualCRL());
        List<X509CRL> crlList = new ArrayList<>();
        try {
            crl.verify(keys.getSecond()[0].getPublicKey());
        } catch (CRLException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException ex) {
            throw new IllegalStateException("CRL is not trusted", ex);
        }
        crlList.add(crl);
        crlList.addAll(getMoreCRLs());
        Logger.trace("Message is: crl loaded");
        System.out.println("Create response entries for crl...");


        Logger.trace( "Message is: before add resp entries");
        Tuple<BigInteger, Optional<OCSPResponse>> responseOpt =
                PredefinedResponses.searchResponseINMap(ocspRequest.getRequestList()[0].getReqCert(), keys);
        if (responseOpt.getSecond().isPresent()) {
            try {
                Logger.trace("Message is: prepared response found");
                 OCSPResponse response = responseOpt.getSecond().get();
                return response;
            } catch (Exception ex) {
                Logger.trace("error getting response" + ex.getMessage());
                Logger.trace(ex);
                throw new IllegalStateException("error getting response" + ex.getMessage(), ex);
            }
        }
        Logger.trace( "Message is: prepared response NOT found looking up revocation...");
        OCSPResponse response = checkCertificateRevocation(ocspRequest, responseGenerator, crl);


        try {
            if (response != null) {
                if (!responseOpt.getFirst().equals(BigInteger.valueOf(-1)) && !responseOpt.getSecond().isPresent()) {
                    Calendar instance = Calendar.getInstance();
                    instance.add(Calendar.MONTH, 1);
                    Date later = new Date();
                    later.setTime(instance.getTimeInMillis());
                    PredefinedResponses.workingData.get().getPreparedResponses().put(responseOpt.getFirst(),
                            new Tuple(later,
                                    new PredefinedResponses.OCSPRespToStore(response, responseOpt.getFirst())));
                }
                PredefinedResponses.writePreparedResponses();
                return response;
            } else {
                AlgorithmID preferred = lookupPrefferedSigAlg(ocspRequest);
                response = getOcspResponse(ocspReqInput, responseGenerator, preferred, keys, nonceExt);
                if (!responseOpt.getFirst().equals(BigInteger.valueOf(-1)) && !responseOpt.getSecond().isPresent()) {
                    Calendar instance = Calendar.getInstance();
                    instance.add(Calendar.MONTH, 1);
                    Date later = new Date();
                    later.setTime(instance.getTimeInMillis());
                    PredefinedResponses.workingData.get().getPreparedResponses().put(responseOpt.getFirst(),
                            new Tuple(later,
                                    new PredefinedResponses.OCSPRespToStore(response, responseOpt.getFirst())));
                }
                PredefinedResponses.writePreparedResponses();
                return response;
            }
        } catch (Exception ex) {
            Logger.trace("Message is: try to output failed with: " + ex.getMessage());
            throw new IllegalStateException("response was not generated ", ex);
        }
    }

    /**
     * really create the OCSP response using the output of the generator
     * @param ocspReqInput the request input
     * @param responseGenerator the initialized generator
     * @param signatureAlgorithm the signature algorithm
     * @param keys the private and public keys used for signing
     * @return the signed response
     */
    private static OCSPResponse getOcspResponse(InputStream ocspReqInput,
                                                ResponseGenerator responseGenerator,
                                                AlgorithmID signatureAlgorithm,
                                                Tuple<PrivateKey,
                                                        X509Certificate[]> keys,
                                                Nonce nonce) throws Exception {
        Logger.trace("before create response internal");// changed public key setting
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.YEAR, 1);
        Date date = new Date();
        date.setTime(cal.getTimeInMillis());
        ArchiveCutoff archiveCutOff = new ArchiveCutoff();
        archiveCutOff.setCutoffTime(date);
        V3Extension[] extensions = new V3Extension[2];
        extensions[0] = archiveCutOff;
        byte [] nonceValue = nonce.getValue();
        extensions[1] = new Nonce(nonceValue);
        OCSPResponse response = responseGenerator.createOCSPResponse(ocspReqInput,
                keys.getSecond()[0].getPublicKey(), signatureAlgorithm, extensions);
        ASN1Object asn1representation = response.toASN1Object();
        Logger.trace("ASN1 formatted response:\n" + asn1representation.toString());
        Logger.trace("after create internal");
        Logger.trace("Message is: output ok");
        return response;
    }

    /**
     * This method checks the revocation and validity state of a given certificate.
     * A certificate can either be good if the issuer is found and the date check is valid and the certificate is in the list
     * ..... or unknown if the certificate is not in the list or revoked if the certificate is in revoked state
     * in the cRL
     * @param ocspRequest the ocsp request
     * @param responseGenerator the response generator for the ocsp response
     * @param crl the certificate revokation list
     * @return a valid ocsp response
     */
    private static OCSPResponse checkCertificateRevocation(OCSPRequest ocspRequest, ResponseGenerator responseGenerator, X509CRL crl) {
        try {
            Request[] requests = ocspRequest.getRequestList();
            for (Request req : requests) {
                ServiceLocator locator = req.getServiceLocator();
                if (locator != null) {
                    AuthorityInfoAccess access = locator.getLocator();
                    if (access != null) {
                        AccessDescription description = access.getAccessDescription(ObjectID.caIssuers);
                        if (description != null) {
                            String uri = description.getUriAccessLocation();
                            if (uri != null) {
                                Logger.trace("Redirected to: " + uri);
                                OCSPRequest newRequest = new OCSPRequest();
                                Request[] requestList = {req};
                                newRequest.setRequestList(requestList);
                                HttpOCSPRequest request = new HttpOCSPRequest
                                        (new URL(uri));
                                request.postRequest(newRequest);
                                OCSPResponse response = request.getOCSPResponse();
                                return response;
                            }
                        }
                    }


                }

                Date endDate = getDate("2024-01-01");
                Date startDate = getDate("2020-01-01");
                Calendar cal = Calendar.getInstance();
                Date actualDate = new Date(cal.getTimeInMillis());
                cal.add(Calendar.WEEK_OF_YEAR, 1);
                Date nextWeek = new Date(cal.getTimeInMillis());
                ReqCert reqCert = req.getReqCert();
                if (reqCert.getType() == ReqCert.certID) {
                    CertID certID = (CertID) reqCert.getReqCert();
                    BigInteger serial = certID.getSerialNumber();
                    AlgorithmID hashAlg = certID.getHashAlgorithm();
                    Date rDate = null;
                    X509Certificate actualCert = getX509Certificate(serial);
                    X509CRL crlAlterntative = null;
                    if (actualCert != null) {
                        crlAlterntative = OCSPCRLClient.getCRLOfCert(actualCert);
                    }
                    if (crlAlterntative != null) {
                        rDate = OCSPCRLClient.checkRevocation(crlAlterntative, serial);
                    } else {
                        rDate = OCSPCRLClient.checkRevocation(crl, serial);
                    }
                    if (rDate == null && actualCert != null) {
                        setResponseEntry(responseGenerator, reqCert, null, actualCert);
                    } else if (actualCert == null && rDate == null) {
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(new UnknownInfo()), actualDate, nextWeek);
                    } else {
                        CRLReason reason = CRLReason.KEY_COMPROMISE;
                        if (crl.containsCertificate(serial) != null
                                || (crlAlterntative != null && crlAlterntative.containsCertificate(serial) != null)) {
                            X509CRLEntry entry = crl.getRevokedCertificate(serial);
                            reason = entry.getRevocationReason();
                        }
                        RevokedInfo info = new RevokedInfo(rDate);
                        info.setRevocationReason(translateRevocationReason(reason));
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(info), actualDate, nextWeek);
                    }


                } else if (reqCert.getType() == ReqCert.pKCert) {
                    X509Certificate certificate = (X509Certificate) reqCert.getReqCert();
                    X509CRL crlToUse = null;
                    crlToUse = getCRLOfCert(certificate);
                    if (crlToUse == null) {
                        crlToUse = crl;
                    }

                    X509CRL crlAlterntative = OCSPCRLClient.getCRLOfCert(certificate);
                    Date rDate = null;
                    if (crlAlterntative != null) {
                        rDate = OCSPCRLClient.checkRevocation(crlAlterntative, certificate.getSerialNumber());
                    } else {
                        rDate = OCSPCRLClient.checkRevocation(crl, certificate.getSerialNumber());
                    }
                    X509Certificate actualCert = getX509Certificate(certificate.getSerialNumber());

                    if (rDate == null && actualCert != null) {
                        setResponseEntry(responseGenerator, reqCert, certificate, actualCert);
                    } else if (actualCert == null && rDate == null) {
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(new UnknownInfo()), actualDate, nextWeek);
                    } else {
                        CRLReason reason = CRLReason.KEY_COMPROMISE;
                        if (crl.containsCertificate(certificate.getSerialNumber()) != null
                        || (crlAlterntative != null && crlAlterntative.containsCertificate(certificate.getSerialNumber()) != null)) {
                            X509CRLEntry entry = crl.getRevokedCertificate(certificate.getSerialNumber());
                            reason = entry.getRevocationReason();
                        }
                        RevokedInfo info = new RevokedInfo(rDate);
                        info.setRevocationReason(translateRevocationReason(reason));
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(info), actualDate, nextWeek);
                    }
                }
            }
            Logger.trace("Message is: generator created");
            System.out.println("Generator created:");
            System.out.println(responseGenerator);
            return null;
        } catch (Exception ex) {
            Logger.trace( "Message is: generator is NOT created due to: " + ex.getMessage());
            Logger.trace(ex);
            return null;
        }
    }

    /**
     * set the response entry by checking the certificate if it seems to be good.
     * @param responseGenerator the response generator
     * @param reqCert the certificate request
     * @param certificate the certificate itself
     * @param actualCert the certificate which is actually checked
     * @throws OCSPException error case
     */
    private static void setResponseEntry(ResponseGenerator responseGenerator, ReqCert reqCert, X509Certificate certificate, X509Certificate actualCert) throws OCSPException {
        Calendar instance = Calendar.getInstance();
        Date actualDate = new Date(instance.getTimeInMillis());
        instance.add(Calendar.WEEK_OF_YEAR, 1);
        Date nextWeek = new Date(instance.getTimeInMillis());

        Optional<X509Certificate> issuer = Optional.empty();
        issuer = CertificateChainUtil.findIssuer(actualCert, PredefinedResponses.workingData.get().getCertificateList());

        boolean matches = false;
        boolean error = false;
        try {
            if (isCertificateSelfSigned(actualCert)) {
                responseGenerator.addResponseEntry(reqCert, new CertStatus(new UnknownInfo()),
                        actualDate, nextWeek);
            }
            actualCert.checkValidity();
        } catch (CertificateExpiredException e) {
            error = true;
        } catch (CertificateNotYetValidException e) {
            error = true;
        }
        if (issuer.isPresent()) {
            matches = moreChecksIfPossible(reqCert, issuer.get(),actualCert);
        } else {

            matches = false;
        }
        if (!error) {
            if (matches) {
                Logger.trace("Found correct certificate : "
                        + actualCert.getSubjectDN().getName());
                if (certificate != null) {
                    responseGenerator.addResponseEntry(reqCert, new CertStatus(), actualDate, nextWeek);
                } else {
                    responseGenerator.addResponseEntry(reqCert, new CertStatus(), actualDate, nextWeek);
                }
            } else {
                Logger.trace("Incorrect certificate found: "
                        + actualCert.getSubjectDN().getName());
                if (certificate != null) {
                    responseGenerator.addResponseEntry(reqCert, new CertStatus(new UnknownInfo()),
                            actualDate, nextWeek);
                } else {
                    responseGenerator.addResponseEntry(reqCert, new CertStatus(new UnknownInfo()),
                            actualDate, nextWeek);
                }
            }
        } else {
            Logger.trace("Certificate is revoked: "
                    + actualCert.getSubjectDN().getName());
            Calendar cal = Calendar.getInstance();
            RevokedInfo info = new RevokedInfo(new Date(cal.getTimeInMillis()));
            info.setRevocationReason(new ReasonCode(ReasonCode.privilegeWithdrawn));
            if (certificate != null) {
                responseGenerator.addResponseEntry(reqCert, new CertStatus(info),
                        actualDate, nextWeek);
            } else {
                responseGenerator.addResponseEntry(reqCert, new CertStatus(info),
                        actualDate, nextWeek);
            }
        }
    }

    /**
     * find the certificate to be checked by its serial
     * @param serial the serial number
     * @return the found certificate
     */
    private static X509Certificate getX509Certificate(BigInteger serial) {
        Optional<X509Certificate> certOpt = findSerialINPositiveList(serial);
        if (certOpt.isPresent()) {
            return certOpt.get();
        } else {
            return null;
        }
    }

    /**
     * Check if the certificate and the issuer fit together and if possible ReqCert.certID
     * check also the hashes for issuers key and name.
     * @param reqCert the certificate request
     * @param issuer the issuer of the certificate to be checked
     * @param cert the certificate to be checked
     * @return return true if all things are matching the needs
     */
    private static boolean moreChecksIfPossible(ReqCert reqCert,
                                                X509Certificate issuer,
                                                X509Certificate cert) {
        if (reqCert.getType() == (ReqCert.certID)) {
            CertID id = (CertID) reqCert.getReqCert();
            if (cert.getSerialNumber().equals(id.getSerialNumber())) {
                AlgorithmID hashAlg = id.getHashAlgorithm();
                try {
                    byte [] keyHash = CertID.calculateIssuerKeyHash(issuer.getPublicKey(), hashAlg);
                    byte [] issuerHash = CertID.calculateIssuerNameHash(
                            (Name)cert.getIssuerDN(), hashAlg);
                    boolean ok = Arrays.equals(id.getIssuerNameHash(), issuerHash);
                    ok = ok && id.isCertIDFor((Name)cert.getIssuerDN(), issuer.getPublicKey(), cert.getSerialNumber());
                    ok = ok && Arrays.equals(id.getIssuerKeyHash(), keyHash);
                    return ok;
                } catch (NoSuchAlgorithmException e) {
                    return false;
                } catch (CodingException e) {
                    return false;
                }

            }
        } else if(reqCert.getType() == (ReqCert.pKCert)) {
            X509Certificate certificate = (X509Certificate) reqCert.getReqCert();
            if (cert.getSerialNumber().equals(certificate.getSerialNumber())) {
                try {
                    return reqCert.isReqCertFor(certificate, issuer, null);
                } catch (OCSPException e) {
                    return false;
                }
            }
            return false;
        } else {
            return true;
        }
        return false;
    }

    /**
     * get the AlgorithmID used for signing the response
     * @param signatureAlgorithm thee initial algorithm
     * @param responderKey the responderKey to be checked
     * @return the algorithm for signimg
     */
    private static AlgorithmID getAlgorithmID(AlgorithmID signatureAlgorithm, PrivateKey responderKey) {
        if (!(responderKey instanceof java.security.interfaces.RSAPrivateKey)) {
            if (responderKey instanceof java.security.interfaces.DSAPrivateKey) {
                signatureAlgorithm = AlgorithmID.dsaWithSHA256;
            } else {
                signatureAlgorithm = AlgorithmID.sha256WithRSAEncryption;
            }
        }
        try {
            Logger.trace("Message is:" + signatureAlgorithm.getImplementationName());
        } catch (Exception ex) {

        }
        return signatureAlgorithm;
    }

    /**
     * get the request signers information from application keystore
     * @return return the private key chain tuple
     */
    public static Tuple<PrivateKey, X509Certificate[]> getPrivateKeyX509CertificateTuple() {
        Tuple<PrivateKey, X509Certificate[]> keys = null;
        KeyStore store = KeyStoreTool.loadAppStore();
        keys = KeyStoreTool.getAppKeyEntry(store);
        return keys;
    }

    /**
     * lookup if the request itself is signed and verify the signature
     * @param ocspRequest the ocsp-request to be checked
     * @throws NoSuchAlgorithmException error case
     * @throws InvalidKeyException error case
     * @throws SignatureException error case
     * @throws OCSPException error case
     */
    private static Nonce checkRequestSigning(OCSPRequest ocspRequest)  {
        if (ocspRequest.containsSignature()) {
            Logger.trace("Request is signed.");



            boolean signatureOk = false;
            X509Certificate signerCert = null;
            if (!signatureOk && ocspRequest.containsCertificates()) {
                Logger.trace("Verifying signature with included signer cert...");
                try {
                    signerCert = ocspRequest.verify();
                } catch (Exception ex) {
                    Logger.trace("Signature not ok from request signer ");
                    return null;
                }
                Logger.trace("Signature ok from request signer " + signerCert.getSubjectDN());
            }
        }
        byte[] nonce;
        Nonce nonceExt = null;
        try {
            nonce = ocspRequest.getNonce();
            if (nonce != null) {
                nonceExt = new Nonce();
                nonceExt.setValue(nonce);
                Logger.trace("Nonce is set to request");
            } else {
                Logger.trace("Nonce is NOT set to request");
            }
            ObjectID[] types = ocspRequest.getAccepatableResponseTypes();
            if (types != null) {
                boolean typeFound = false;
                for (ObjectID type : types) {
                    if (type == ObjectID.basicOcspResponse) {
                        typeFound = true;
                    }
                }
                if (!typeFound) {
                    Logger.trace("accepted type not set");
                    return nonceExt;
                } else {
                    Logger.trace("accepted type set");
                    return nonceExt;
                }

            }
            return nonceExt;

        } catch (Exception ex) {
            return nonceExt;
        }
    }

    /**
     * Reads a X.509 crl from the given file.
     *
     * @param is the name of the crl file
     * @return the crl
     */
    public static X509CRL readCrl(InputStream is) {

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

    /**
     * lookup if there are more CRLs in the path and load them
     * @return the list of CRL objects
     */
    private static List<X509CRL> getMoreCRLs() {
        List<X509CRL> result = new ArrayList<>();
        File trustDir = new File(APP_DIR_TRUST);
        if (trustDir.exists() && trustDir.isDirectory()) {
            File[] list = trustDir.listFiles();
            for (File file : list) {
                if (file.getAbsolutePath().contains(".crl")) {
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

    /**
     * get a valid date object for a given string
     * @param newDate the fresh date
     * @return the date object
     */
    private static java.util.Date getDate(String newDate) {
        SimpleDateFormat textFormat = new SimpleDateFormat("yyyy-MM-dd");
        String paramDateAsString = newDate;
        java.util.Date myDate = null;

        try {
            myDate = textFormat.parse(paramDateAsString);
            return myDate;
        } catch (Exception ex) {
            return null;
        }
    }

    /**
     * Convert the revocation reason between the formats of crl and revokation info
     * @param reason the revocation reason
     * @return the translated reason
     */
    private static ReasonCode translateRevocationReason(CRLReason reason) {
        ReasonCode result;
        switch (reason) {

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

    /**
     * Here the keystore holdiung the known certificates is loaded
     */
    public static void loadActualPrivStore() {
        loadActualTrustLists();
        try {
            Logger.trace("Before loading private key-store....");
            String password = decryptPassword("pwdFile");
            File keyFile = new File(APP_DIR_TRUST, "privKeystore" + ".p12");
            KeyStore storeApp = KeyStoreTool.loadStore(new FileInputStream(keyFile),
                    password.toCharArray(), "UnicP12");
            Logger.trace("key-store loaded reading certificates ....");
            Enumeration<String> aliasEnum = storeApp.aliases();
            while (aliasEnum.hasMoreElements()) {
                String alias = aliasEnum.nextElement();
                Logger.trace("Try to read alias: " + alias);
                X509Certificate[] chain = KeyStoreTool.getCertChainEntry(storeApp, alias);
                List<X509Certificate> temp = CertificateChainUtil
                        .addToCertificateList(chain, PredefinedResponses.workingData.get().getCertificateList());
                PredefinedResponses.workingData.get().setCertificateList(temp);
            }
            Logger.trace("loading private key-store ok....");
        } catch (Exception ex) {
            Logger.trace("not loaded cause is: " + ex.getMessage());
            throw new IllegalStateException("not loaded keys", ex);
        }
    }

    /**
        * Load the trusted
     */
    public static void loadActualTrustLists() {
        try {
            Logger.trace("Before loading private trust list....");
            File trustDir = new File(APP_DIR_TRUST);
            if (trustDir.isDirectory()) {
                FilenameFilter filter = new FilenameFilter() {
                    @Override
                    public boolean accept(File dir, String name) {
                        if (name.endsWith("xml")) {
                            return true;
                        } else {
                            return false;
                        }
                    }
                };
                File[] files = trustDir.listFiles(filter);
                Logger.trace(files.length + " trust lists found");
                for (File trustFile : files) {
                    TrustListLoader loader = new TrustListLoader(true);
                    if (trustFile.exists()) {
                        TrustListManager manager = loader.getManager(trustFile);
                        X509Certificate[] array = manager.getAllCerts()
                                .toArray(new X509Certificate[manager.getAllCerts().size()]);
                        CertificateChainUtil.addToCertificateList(array, PredefinedResponses.workingData.get().getCertificateList());
                        Logger.trace("loading trust list:" + trustFile.getName() + " ok....");
                    }

                }
            }

        } catch (Exception ex) {
            Logger.trace("not loaded cause is: " + ex.getMessage());
            throw new IllegalStateException("not loaded keys", ex);
        }

    }


    /**
     * Find the input for the actual CRL
     * @return the input stream of the CRL
     */
    public static InputStream loadActualCRL() {
        File crlFile = new File(APP_DIR_TRUST, "privRevokation" + ".crl");
        Logger.trace("CRL list file is: " + crlFile.getAbsolutePath());
        try {
            if (crlFile.exists()) {
                Logger.trace("CRL list file is about to load: " + crlFile.getAbsolutePath());
                return new FileInputStream(crlFile);

            } else {
                InputStream input = UnicHornResponderUtil.class.getResourceAsStream("/unichorn.crl");
                return input;
            }
        } catch (IOException ex) {
            Logger.trace("CRL list file is exceptional: " + crlFile.getAbsolutePath() + ex.getMessage()
            );
            throw new IllegalStateException("get input stream failed", ex);
        }

    }

    /**
     * Lookup a certificate chain in the list of certificates by it's serial number
     * @param serial the certificates serial
     * @return the certificate chain in a optional or empty if there is none.
     */
    private static Optional<X509Certificate> findSerialINPositiveList(BigInteger serial) {
        Optional<X509Certificate> opt = PredefinedResponses.workingData.get().getCertificateList().stream().filter(e -> {
            X509Certificate cert = e;
            Logger.trace("Search for: " + serial.toString(10) +  " in --> " + cert.toString(true));
            if (cert.getSerialNumber().equals(serial)) {
                return true;
            }
            return false;
        }).findFirst();
        return opt;
    }

    /**
     * This method adds the entries of a given keystore to an existing keystore
     * @param keyFile the store file
     * @param storeToApply the store with the keys to be added
     * @param passwd the store password
     * @param storeType the store type
     */
    public static void applyKeyStore(File keyFile, KeyStore storeToApply, String passwd, String passwdUser,String storeType) {
        try {
            ExecutorService executor = Executors.newFixedThreadPool(5);
            Future<?> task = executor.submit(new WorkerThread(keyFile, storeToApply, passwd, passwdUser,storeType));
            task.get(10, TimeUnit.MINUTES);
            executor.shutdown();
        } catch (Exception ex) {
            Logger.trace("thread failed with:" + ex.getMessage());
            throw new IllegalStateException("thread failed with:", ex);
        }

    }

    /**
     * This method adds the entries of a given keystore to an existing keystore
     * @param keyFile the store file
     * @param keyToApply the private key to apply
     * @param chainToApply the certificate chain to apply
     * @param passwd the store password
     * @param storeType the store type
     */
    public static void applyKeyStore(File keyFile, PrivateKey keyToApply,
                                     X509Certificate[] chainToApply,
                                     String passwd, String storeType) {
        try {
            KeyStore privStore;

            ExecutorService executor = Executors.newFixedThreadPool(5);
            try {
                if (!keyFile.exists()) {
                    privStore = KeyStoreTool.initStore(storeType, passwd);
                } else {
                    privStore = KeyStoreTool.loadStore(new FileInputStream(keyFile), passwd.toCharArray(), storeType);
                }
                verifier.verifyChain(chainToApply);
                Logger.trace("Add key and chain");
                KeyStoreTool.addKey(privStore,
                        keyToApply,
                        passwd.toCharArray(),
                        chainToApply,
                        chainToApply[0].getSubjectDN().getName());
                Logger.trace("Before storing.... :" + keyFile.getAbsolutePath());
                OutputStream out = new FileOutputStream(keyFile);
                KeyStoreTool.storeKeyStore(privStore, out, passwd.toCharArray());
                out.close();
                Logger.trace("Success storing.... :" + keyFile.getAbsolutePath());
            } catch (Exception ex) {
                Logger.trace("thread failed with:" + ex.getMessage());
                throw new IllegalStateException("thread failed with:", ex);
            }

        } catch (Exception ex) {
            throw new IllegalStateException("apply to store failed", ex);
        }
    }


    /**
     * Encrypt the key store pass and write it to a file
     * @param fName thefile-name
     * @param password the password to be encrypted
     */
    public static void encryptPassword(String fName, String password) {
        File pwdFile = new File(APP_DIR, fName);
        File pwdFileOut = new File(APP_DIR, fName + ".encr");
        try {
            byte[] out = password.getBytes();
            FileOutputStream outFile = new FileOutputStream(pwdFile);
            outFile.write(out);
            outFile.close();
            SigningUtil util = new SigningUtil();
            SigningBean bean = new SigningBean().setDataIN(new FileInputStream(pwdFile))
                    .setOutputPath(pwdFileOut.getAbsolutePath())
                    .setCryptoAlgorithm(CryptoAlg.PBE_SHAA3_KEY_TRIPLE_DES_CBC)
                    .setDecryptPWD("secretthing");
            DataSource dsEncrypt = util.encryptCMS(bean);
            util.writeToFile(dsEncrypt, bean);
            pwdFile.delete();
        } catch (Exception ex) {
            Logger.trace("error writing pwd" + ex.getMessage());
            throw new IllegalStateException("error writing encrypted pwd", ex);
        }

    }

    /**
     * Decrypt the password stored in a password file
     * @param fName the file name
     * @return the decrypted password
     */
    public static String decryptPassword(String fName) {
        File pwdFile = new File(APP_DIR, fName);
        File pwdFileOut = new File(APP_DIR, fName + ".encr");
        try {
            SigningUtil util = new SigningUtil();
            SigningBean bean = new SigningBean().setDataIN(new FileInputStream(pwdFileOut))
                    .setOutputPath(pwdFile.getAbsolutePath())
                    .setCryptoAlgorithm(CryptoAlg.PBE_SHAA3_KEY_TRIPLE_DES_CBC)
                    .setDecryptPWD("secretthing");
            DataSource dsEncrypt = util.decryptCMS(bean);
            util.writeToFile(dsEncrypt, bean);
            FileInputStream input = new FileInputStream(pwdFile);
            byte [] buffer = new byte[100];
            int read = input.read(buffer);
            String pwd = new String(buffer, 0, read);
            input.close();
            pwdFile.delete();
            return pwd;
        } catch (Exception ex) {
            Logger.trace("error writing pwd" + ex.getMessage());
            throw new IllegalStateException("error reading encrypted pwd", ex);
        }

    }

    /**
     * read extension for preferred signature algorithm and lookup algorithm
     * @param request the ocsp-request
     * @return the preferred algorithm or default
     * @throws Exception error case
     */
    public static AlgorithmID lookupPrefferedSigAlg(OCSPRequest request) throws Exception {
        AlgorithmID result = AlgorithmID.sha256;
        PreferredSignatureAlgorithms extension = (PreferredSignatureAlgorithms)request
                .getExtension(ObjectID.ocspExt_PreferredSignatureAlgorithms);
        if (extension != null) {
            PreferredSignatureAlgorithms.PreferredSignatureAlgorithm[] algArray =
                    extension.getAlgorithms();
            result = algArray[0].getSigIdentifier();
        }
        return result;
    }

}
