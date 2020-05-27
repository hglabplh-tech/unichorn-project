package org.harry.security.util.ocsp;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AccessDescription;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.GeneralName;
import iaik.asn1.structures.Name;
import iaik.cms.IssuerAndSerialNumber;
import iaik.utils.CryptoUtils;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.AuthorityInfoAccess;
import iaik.x509.extensions.ExtendedKeyUsage;
import iaik.x509.ocsp.*;
import iaik.x509.ocsp.extensions.ArchiveCutoff;
import iaik.x509.ocsp.extensions.CrlID;
import iaik.x509.ocsp.extensions.PreferredSignatureAlgorithms;
import iaik.x509.ocsp.extensions.ServiceLocator;
import iaik.x509.ocsp.utils.TrustedResponders;

import java.math.BigInteger;
import java.security.*;
import java.util.Date;

public class OCSPClient {

    private X509Certificate[] targetCerts;
    private ReqCert reqCert;

    private byte[] nonce;
    // the signature algorithm
    AlgorithmID signatureAlgorithm = AlgorithmID.sha256WithRSAEncryption;

    // hash algorithm for CertID
    AlgorithmID hashAlgorithm = AlgorithmID.sha256;

    // trust repository for responders
    TrustedResponders trustedResponders = null;

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
     * @param includeExtensions
     *          if extensions shall be included
     *
     * @return the OCSPRequest created
     *
     * @exception OCSPException
     *              if an error occurs when creating the request
     */
    public OCSPRequest createOCSPRequest(PrivateKey requestorKey,
                                         X509Certificate[] requestorCerts,
                                         X509Certificate[] targetCerts,
                                         boolean includeExtensions, int type,
                                         String altResponder)
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

            if (includeExtensions) {
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
            }

            // create the OCSPRequest
            OCSPRequest ocspRequest = new OCSPRequest();

            // set the requestList
            ocspRequest.setRequestList(new Request[] { request });

            if (includeExtensions) {
                // we only accept basic OCSP responses
                ocspRequest
                        .setAcceptableResponseTypes(new ObjectID[] { BasicOCSPResponse.responseType });

                // set a nonce value
                nonce = new byte[16];
                SecureRandom random = new SecureRandom();
                random.nextBytes(nonce);
                ocspRequest.setAcceptableResponseTypes(new ObjectID[]{BasicOCSPResponse.responseType});
                ocspRequest.setNonce(nonce);
                PreferredSignatureAlgorithms.PreferredSignatureAlgorithm [] algorithms = new PreferredSignatureAlgorithms.PreferredSignatureAlgorithm[4];
                algorithms[0] = new PreferredSignatureAlgorithms.PreferredSignatureAlgorithm(AlgorithmID.sha3_256WithRSAEncryption);
                algorithms[1] = new PreferredSignatureAlgorithms.PreferredSignatureAlgorithm(AlgorithmID.sha3_512WithRSAEncryption);
                algorithms[2] = new PreferredSignatureAlgorithms.PreferredSignatureAlgorithm(AlgorithmID.sha256WithRSAEncryption);
                algorithms[3] = new PreferredSignatureAlgorithms.PreferredSignatureAlgorithm(AlgorithmID.sha512WithRSAEncryption);
                PreferredSignatureAlgorithms algorithmsExt = new PreferredSignatureAlgorithms(algorithms);
                ocspRequest.addExtension(algorithmsExt);

            }


            if (requestorKey != null) {
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
            try {
                singleResponse = basicOCSPResponse.getSingleResponse(this.reqCert);
            } catch (OCSPException ex) {
                System.out.println(ex.getMessage());
                System.out.println("Try again...");
                singleResponse = basicOCSPResponse.getSingleResponse(this.targetCerts[0],
                        this.targetCerts[1], null);
            }

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
            byte[] respondedNonce = basicOCSPResponse.getNonce();
            if (respondedNonce != null) {
                if (!CryptoUtils.secureEqualsBlock(this.nonce, respondedNonce)) {
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



}
