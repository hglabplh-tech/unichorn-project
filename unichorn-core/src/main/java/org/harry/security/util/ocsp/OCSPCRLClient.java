package org.harry.security.util.ocsp;

import iaik.asn1.ASN1Object;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.*;
import iaik.cms.IssuerAndSerialNumber;
import iaik.utils.CryptoUtils;
import iaik.x509.RevokedCertificate;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.X509ExtensionInitException;
import iaik.x509.extensions.AuthorityInfoAccess;
import iaik.x509.extensions.CRLDistributionPoints;
import iaik.x509.extensions.ExtendedKeyUsage;
import iaik.x509.ocsp.*;
import iaik.x509.ocsp.extensions.*;
import iaik.x509.ocsp.utils.TrustedResponders;
import org.harry.security.util.CertificateWizzard;
import org.pmw.tinylog.Logger;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.security.*;
import java.util.*;

public class OCSPCRLClient {

    private X509Certificate[] targetCerts;
    private ReqCert reqCert;

    private byte[] nonce;
    // the signature algorithm
    AlgorithmID signatureAlgorithm = AlgorithmID.sha256WithRSAEncryption;

    // hash algorithm for CertID
    AlgorithmID hashAlgorithm = AlgorithmID.sha256;

    // trust repository for responders
    TrustedResponders trustedResponders = null;

    public static boolean checkCertificateForRevocation(X509Certificate[] certificates) {
        boolean success = true;
        try {
            for (X509Certificate certificate : certificates) {
                boolean ok = false;
                X509CRL crl = getCRLOfCert(certificate);
                if (crl != null) {
                    Date revokeDate = checkRevocation(crl, certificate.getSerialNumber());
                    if (revokeDate == null) {
                        ok = true;
                    }
                    success = success && ok;
                } else {
                    success = false;
                }
            }
            return success;
        } catch (Exception ex) {
            throw new IllegalStateException("cannot check CRL error: " + ex.getMessage(), ex);
        }
    }

    /**
     * Check if the given certificate is in the revokation list and has to be revoked.
     * The method looks up the certificate and checks it's revocation state.
     * @param crl the revocation list
     * @param certSerial the certificates serial     *
     * @return a possible revocation Date
     */
    public static Date checkRevocation(X509CRL crl, BigInteger certSerial) {
        Set<RevokedCertificate> revoked = crl.getRevokedCertificates();
        for (RevokedCertificate cert : revoked) {
            System.out.println(cert.getSerialNumber() + " " + certSerial);
        }
        Optional<RevokedCertificate> found = revoked.stream()
                .filter(e -> e.getSerialNumber().equals(certSerial))
                .findFirst();
        if (found.isPresent()) {
            Calendar cal = Calendar.getInstance();
            Date actualDate = new Date(cal.getTimeInMillis());
            Date rDate = found.get().getRevocationDate();
            if (rDate.after(actualDate)) {
                return null;
            } else {
                return rDate;
            }

        }
        return null;
    }

    /**
     * Get the CRL from the certificate
     * @param cert the certificate
     * @return the X509CRL from the specified extension
     * @throws X509ExtensionInitException error case
     */
    public static X509CRL getCRLOfCert(X509Certificate cert) throws X509ExtensionInitException {
        String urlString = null;
        CRLDistributionPoints access = (CRLDistributionPoints) cert.getExtension(ObjectID.certExt_CrlDistributionPoints);
        if (access != null) {
            Enumeration<DistributionPoint> enumDist = access.getDistributionPoints();
            boolean hasMore = enumDist.hasMoreElements();
            if (hasMore) {
                DistributionPoint point = enumDist.nextElement();
                try {
                    X509CRL crl = point.loadCrl();
                    return crl;
                } catch (Exception ex) {
                    throw new IllegalStateException("load crl failed", ex);
                }
            } else {
                return null;
            }
        } else {
            return null;

        }
    }

    /**
     * Get the responder URL from the certificate
     * @param cert the certificate
     * @return the URL from the specified extension
     * @throws X509ExtensionInitException error case
     * @throws MalformedURLException error case
     */
    public static String getOCSPUrl(X509Certificate cert) throws X509ExtensionInitException, MalformedURLException {
        String urlString = null;
        AuthorityInfoAccess access = (AuthorityInfoAccess)cert.getExtension(ObjectID.certExt_AuthorityInfoAccess);
        if (access != null) {
            AccessDescription description = access.getAccessDescription(ObjectID.ocsp);
            urlString = description.getUriAccessLocation();
            return urlString;
        }
        return null;
    }

    /**
     * Creates an OCSPRequest.
     *
     * @param requestorKey
     *          the private key of the requestor, or <code>null</code> if the
     *          request shall not be signed
     * @param requestorCerts
     *          if the request shall be signed (requestorKey != null) and signer
     *          certs shall be included
     * @param targetCerts
     *          the certs for which status information shall be included
     * @param additionalExts
     * @return the OCSPRequest created
     *
     * @exception OCSPException
     *              if an error occurs when creating the request
     */
    public OCSPRequest createOCSPRequest(PrivateKey requestorKey,
                                         X509Certificate[] requestorCerts,
                                         X509Certificate[] targetCerts,
                                         int type,
                                         String altResponder, boolean additionalExts)
            throws OCSPException

    {

        if (targetCerts != null) {
            this.targetCerts = (X509Certificate[]) targetCerts.clone();
            try {
                reqCert = createReqCert(targetCerts, hashAlgorithm, type);
            } catch (Exception ex) {
                throw new OCSPException("Error creating cert id: " + ex.toString());
            }
        }

        if (reqCert == null) {
            throw new OCSPException("Cannot create ocsp request from null cert id!");
        }

        try {

            // create a single request for the target cert identified by the reqCert
            Request request = new Request(reqCert);


            if (requestorCerts != null && altResponder != null) {
                // include service locator
                ObjectID accessMethod = ObjectID.caIssuers;
                GeneralName accessLocation = new GeneralName(
                        GeneralName.uniformResourceIdentifier, altResponder);
                AccessDescription accessDescription = new AccessDescription(accessMethod,
                        accessLocation);
                AuthorityInfoAccess locator = new AuthorityInfoAccess(accessDescription);
                ServiceLocator serviceLocator = new ServiceLocator(
                        (Name) requestorCerts[0].getSubjectDN());
                serviceLocator.setLocator(locator);
                request.setServiceLocator(serviceLocator);
            }


            // create the OCSPRequest
            OCSPRequest ocspRequest = new OCSPRequest();

            // set the requestList
            ocspRequest.setRequestList(new Request[] { request });

            // set a nonce value
            nonce = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(nonce);
            ocspRequest.setAcceptableResponseTypes(new ObjectID[]{BasicOCSPResponse.responseType});
            ocspRequest.setNonce(nonce);
            // we only accept basic OCSP responses
            ocspRequest
                    .setAcceptableResponseTypes(new ObjectID[] { BasicOCSPResponse.responseType });

            if (additionalExts) {
                PreferredSignatureAlgorithms.PreferredSignatureAlgorithm[] algorithms = new PreferredSignatureAlgorithms.PreferredSignatureAlgorithm[4];
                algorithms[0] = new PreferredSignatureAlgorithms.PreferredSignatureAlgorithm(AlgorithmID.sha3_256WithRSAEncryption);
                algorithms[1] = new PreferredSignatureAlgorithms.PreferredSignatureAlgorithm(AlgorithmID.sha3_512WithRSAEncryption);
                algorithms[2] = new PreferredSignatureAlgorithms.PreferredSignatureAlgorithm(AlgorithmID.sha256WithRSAEncryption);
                algorithms[3] = new PreferredSignatureAlgorithms.PreferredSignatureAlgorithm(AlgorithmID.sha512WithRSAEncryption);
                PreferredSignatureAlgorithms algorithmsExt = new PreferredSignatureAlgorithms(algorithms);
                ocspRequest.addExtension(algorithmsExt);
            }




            if (requestorKey != null && additionalExts) {
                if ((requestorCerts == null) || (requestorCerts.length == 0)) {
                    throw new NullPointerException(
                            "Requestor certs must not be null if request has to be signed!");
                }
                // set the requestor name
                ocspRequest.setRequestorName(new GeneralName(GeneralName.directoryName,
                        requestorCerts[0].getSubjectDN()));
                // include signing certificates
                ocspRequest.setCertificates(requestorCerts);
                // sign the request
                ocspRequest.sign(signatureAlgorithm, requestorKey);
            }
            System.out.println("Request created:");
            System.out.println(ocspRequest.toString(true));

            return ocspRequest;

        } catch (Exception ex) {
            throw new OCSPException(ex.toString());
        }

    }
    /**
     * Calculates an ReqCert of type <code>certID</code> from the given target
     * certificates.
     *
     * @param targetCerts
     *          the target certificate chain containing the target certificate
     *          (for which OCSP status information is requested) at index 0
     * @param hashAlgorithm
     *          the hash algorithm to be used
     *
     * @return the ReqCert
     *
     * @throws Exception
     *           if an exception occurs
     */
    final static ReqCert createReqCert(X509Certificate[] targetCerts,
                                       AlgorithmID hashAlgorithm, int type)
            throws Exception
    {

        if ((targetCerts == null) || (targetCerts.length == 0)) {
            throw new NullPointerException("targetCerts must not be null!");
        }
        if (hashAlgorithm == null) {
            throw new NullPointerException("hashAlgorithm must not be null!");
        }

        // calculate certID

        // issuer name
        Name issuerName = (Name) targetCerts[0].getIssuerDN();
        PublicKey issuerKey = targetCerts[1].getPublicKey();
        BigInteger serialNum = targetCerts[0].getSerialNumber();
        // create the certID
        try {
            if (type == ReqCert.certID) {
                CertID certID = new CertID(hashAlgorithm, issuerName, issuerKey,
                        serialNum);
                System.err.println("Issuer Serial: " + targetCerts[1].getSerialNumber());
                return new ReqCert(ReqCert.certID, certID);
            } else if (type == ReqCert.pKCert) {
                return new ReqCert(ReqCert.pKCert, targetCerts[0]);
            } else if(type == ReqCert.issuerSerial) {
                IssuerAndSerialNumber number = new IssuerAndSerialNumber(
                        (Name)targetCerts[0].getIssuerDN(),targetCerts[0].getSerialNumber());
                return new ReqCert(ReqCert.issuerSerial, number);
            } else {
                return new ReqCert(ReqCert.certHash, targetCerts[0]);
            }

        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("No implementation for SHA!");
        }

    }

    /**
     * Parses an ocsp response received and looks for the single responses
     * included.
     *
     * @param ocspResponse
     *          the OCSP response
     * @param includeExtensions
     *          whether there have been extensions included in the request and
     *          therefore have to be checked now (Nonce)
     *
     * @exception OCSPException
     *              if an error occurs when creating the response
     */
    public int parseOCSPResponse(OCSPResponse ocspResponse, boolean includeExtensions)
            throws OCSPException
    {

        try {

            // get the response status:
            int responseStatus = ocspResponse.getResponseStatus();

            if (responseStatus != OCSPResponse.successful) {
                System.out.println("Not successful; got response status: "
                        + ocspResponse.getResponseStatusName());
                return responseStatus;
            }
            ASN1Object asn1representation = ocspResponse.toASN1Object();
            System.out.println("ASN1 formatted response:\n" + asn1representation.toString());
            // response successful
            System.out.println("Succesful OCSP response:");
            System.out.println(ocspResponse.toString());

            // get the basic ocsp response (the only type we support; otherwise an
            // UnknownResponseException would have been thrown during parsing the
            // response
            BasicOCSPResponse basicOCSPResponse = (BasicOCSPResponse) ocspResponse
                    .getResponse();
            X509Certificate signer = basicOCSPResponse.getSignerCertificate();

            // we verify the response
            try {
                if (basicOCSPResponse.containsCertificates()) {
                    X509Certificate signerCert = basicOCSPResponse.verify();
                    System.out.println("Signature ok from response signer "
                            + signerCert.getSubjectDN());

                    // trusted responder?
                    if (!signerCert.equals(this.targetCerts[1])) {
                        // authorized for signing
                        ExtendedKeyUsage extendedKeyUsage = (ExtendedKeyUsage) signerCert
                                .getExtension(ExtendedKeyUsage.oid);
                        boolean ocspSigning = false;
                        if (extendedKeyUsage != null) {
                            ObjectID[] purposes = extendedKeyUsage.getKeyPurposeIDs();
                            for (int i = 0; i < purposes.length; i++) {
                                if (purposes[i].equals(ExtendedKeyUsage.ocspSigning)) {
                                    ocspSigning = true;
                                    break;
                                }
                            }
                        }
                        if (trustedResponders != null) {
                            if (!(ocspSigning && trustedResponders.isTrustedResponder(
                                    basicOCSPResponse.getResponderID(), signerCert, targetCerts[1]))) {
                                System.out.println("WARNING: Responder not trusted! Reject response!!!");
                            }
                        } else {
                            if (ocspSigning) {
                                if (signerCert.getIssuerDN().equals(this.targetCerts[1].getSubjectDN())) {
                                    System.out
                                            .println("WARNING: Responder authorized by target cert issuer, but no trust information available!");
                                } else {
                                    System.out
                                            .println("WARNING: Responder cert has ocspSigning ExtendedKeyUsage, but is not issued by target cert issuer!");
                                }
                            } else {
                                System.out
                                        .println("WARNING: Responder not equal to target cert issuer and not authorized for OCSP signing!");
                            }
                        }
                    }
                } else {
                    System.out
                            .println("Certificates not included; try to verify with issuer target cert...");
                    basicOCSPResponse.verify(this.targetCerts[1].getPublicKey());
                    System.out.println("Signature ok!");
                }
            } catch (SignatureException ex) {
                System.out.println("Signature verification error!!!");
            }

            System.out.println("Response produced at :" + basicOCSPResponse.getProducedAt());

            ResponderID responderID = basicOCSPResponse.getResponderID();
            System.out.println("ResponderID: " + responderID);

            // look if we got an answer for our request:
            SingleResponse singleResponse = null;

            singleResponse = basicOCSPResponse.getSingleResponses()[0];


            if (singleResponse != null) {
                System.out.println("Status information got for cert: ");
                System.out.println(singleResponse.getCertStatus());
                System.out.println("This Update: " + singleResponse.getThisUpdate());
                Date now = new Date();
                // next update included?
                Date nextUpdate = singleResponse.getNextUpdate();
                if (nextUpdate != null) {
                    System.out.println("Next Update: " + nextUpdate);
                    if (nextUpdate.before(now)) {
                        System.out
                                .println("WARNING: There must be more recent information available!");
                    }
                }
                // check thisUpdate date
                Date thisUpdate = singleResponse.getThisUpdate();
                if (thisUpdate == null) {
                    System.out.println("Error: Missing thisUpdate information!");
                } else {
                    if (thisUpdate.after(now)) {
                        System.out
                                .println("WARNING: Response yet not valid! thisUpdate (" + thisUpdate
                                        + ") is somewhere in future (current date is: " + now + ")!");
                    }
                }
                // archive cutoff included?
                Date archiveCutoffDate = singleResponse.getArchiveCutoff();
                if (archiveCutoffDate != null) {
                    System.out.println("archivCutoffDate: " + archiveCutoffDate);
                } else {
                    ArchiveCutoff cutoff = (ArchiveCutoff) basicOCSPResponse.getExtension(ObjectID.ocspExt_ArchiveCutoff);
                    if (cutoff != null) {
                        Date cutoffDate = cutoff.getCutoffTime();
                        System.out.println("archivCutoffDate: " + cutoffDate);
                    }
                }
                // crl id included?
                CrlID crlID = singleResponse.getCrlID();
                if (crlID != null) {
                    System.out.println("crlID: " + crlID);
                }
            } else {
                System.out.println("No response got for our request!");
            }

            // nonce check
            Nonce respondedNonce = (Nonce)basicOCSPResponse.getExtension(ObjectID.ocspExt_Nonce);
            if (respondedNonce != null) {
                if (!CryptoUtils.secureEqualsBlock(this.nonce, respondedNonce.getValue())) {
                    System.out.println("Error!!! Nonce values do not match!");
                }
            } else {
                if ((includeExtensions == true) && (this.nonce != null)) {
                    System.out.println("Error!!! Nonce not returned in server response!");
                }
            }
            return responseStatus;
        } catch (UnknownResponseException ex) {
            System.out
                    .println("This response is successful but contains an unknown response type:");
            UnknownResponseException unknown = ex;
            System.out.println("Unknown type: " + unknown.getResponseType());
            System.out.println("ASN.1 structure:");
            System.out.println(unknown.getUnknownResponse().toString());
            return OCSPResponse.internalError;
        } catch (NoSuchAlgorithmException ex) {
            throw new OCSPException("Error while verifying signature: " + ex.getMessage());
        } catch (InvalidKeyException ex) {
            throw new OCSPException("Error while verifying signature: " + ex.getMessage());
        } catch (Exception ex) {
            throw new OCSPException(ex.getMessage());
        }
    }

    /**
     * Class representing a version of the status code
     */
    public static enum CertStatusEnum {
        GOOD(0, "good"),
        REVOKED(1,"revoked"),
        UNKNOWN(2, "unknown");

        private final int status;

        private final String statusText;

        CertStatusEnum(int status, String statusText) {
            this.status = status;
            this.statusText = statusText;
        }

        public int getStatus() {
            return status;
        }

        public String getStatusText() {
            return statusText;
        }

        public static CertStatusEnum fromStatus(int status) {
            for(CertStatusEnum element: CertStatusEnum.values()) {
                if (status == element.getStatus()) {
                    return element;
                }
            }
            return null;
        }

        public static CertStatusEnum fromStatusText(String statusText) {
            for(CertStatusEnum element: CertStatusEnum.values()) {
                if (statusText.equals(element.getStatusText())) {
                    return element;
                }
            }
            return null;
        }
    }

    public static String extractResponseStatusName(OCSPResponse ocspResponse) {
        if (ocspResponse.getResponseStatus() == OCSPResponse.successful) {
            BasicOCSPResponse basicOCSPResponse = (BasicOCSPResponse) ocspResponse
                    .getResponse();
            SingleResponse single = basicOCSPResponse.getSingleResponses()[0];
            return single.getCertStatus().getCertStatusName();
        } else {
            return "bad";
        }
    }



}
