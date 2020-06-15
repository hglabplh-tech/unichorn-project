package org.harry.security.util.ocsp;

import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.*;
import org.harry.security.util.Tuple;
import org.pmw.tinylog.Logger;

import java.io.*;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.*;

import static org.harry.security.CommonConst.APP_DIR_WORKING;

public class PredefinedResponses {
    /**
     * The positive list of certificate chains which are known
     */

    public static ThreadLocal<LocalCache> workingData
            = new ThreadLocal<>();

    /**
     * Read the responses hash-table if available
     * @throws IOException error case
     * @throws ClassNotFoundException error case
     */
    public static void initStorePreparedResponses() throws IOException, ClassNotFoundException {
        try {
            workingData.get().setPreparedResponses(new HashMap<BigInteger, Tuple<Date, OCSPRespToStore>>());
            File hashMapFile = new File(APP_DIR_WORKING, "responses.ser");
            if (hashMapFile.exists()) {
                ObjectInputStream input = new ObjectInputStream(new FileInputStream(hashMapFile));
                Object rawObj = input.readObject();
                if (rawObj != null) {
                    workingData.get().setPreparedResponses((HashMap) rawObj);
                }
                input.close();
            } else {
                Logger.trace("Prepared responses file not found");
            }
        } catch (Exception ex) {
            Logger.trace("read HashTable failed: " +  ex.getMessage());
            throw new IllegalStateException("read HashTable failed", ex);
        }
    }

    /**
     * write the responses hash-table to disk
     * @throws IOException error case
     */
    public static void writePreparedResponses() throws IOException {
        try {
            File hashMapFile = new File(APP_DIR_WORKING, "responses.ser");
            ObjectOutputStream output = new ObjectOutputStream(new FileOutputStream(hashMapFile));
            output.writeObject(workingData.get().getPreparedResponses());
            output.flush();
            output.close();
        } catch (Exception ex) {
            Logger.trace("write HashTable failed: " +  ex.getMessage());
            throw new IllegalStateException("write HashTable failed", ex);
        }
    }

    /**
     * Search response in hash-table
     * @param req the cert-req of the actual request used to get the serial
     * @param keys the information for response signing
     * @return a tuple of the serial and th optional of the response
     */
    public static Tuple<BigInteger, Optional<OCSPResponse>> searchResponseINMap(ReqCert req, Tuple<PrivateKey,
            X509Certificate[]> keys) {
        try {
            BigInteger serial = null;
            if (req.getType() == ReqCert.certID) {
                CertID certID = (CertID) req.getReqCert();
                serial = certID.getSerialNumber();
            } else if (req.getType() == ReqCert.pKCert) {
                X509Certificate cert = (X509Certificate) req.getReqCert();
                serial = cert.getSerialNumber();
            } else {
                Logger.trace("Entry not found");
                return new Tuple<>(BigInteger.valueOf(-1), Optional.empty());
            }
            if (serial != null) {
                Tuple<Date, OCSPRespToStore> respToStore = workingData.get().getPreparedResponses().get(serial);
                OCSPResponse response = null;
                if (respToStore != null) {
                    response = transferToOCSPResponse(respToStore.getSecond(), keys);
                    performOptionalRemove(serial, respToStore);
                }
                if (response != null) {
                    return new Tuple<>(serial, Optional.of(response));
                } else {
                    return new Tuple<>(serial, Optional.empty());
                }
            }
            return new Tuple(serial, Optional.empty());
        } catch (Exception ex) {
            Logger.trace("Error during conversion: " + ex.getMessage() + " type " + ex.getClass().getCanonicalName());
            throw new IllegalStateException("cannot convert to OCSPResponse", ex);
        }

    }

    private static void performOptionalRemove(BigInteger serial, Tuple<Date, OCSPRespToStore> respToStore) {
        Date deleteDate = respToStore.getFirst();
        if (deleteDate.compareTo(new Date()) >= 0) {
            workingData.get().getPreparedResponses().remove(serial);
        }
    }

    /**
     * Method to restore a OCSPResponse object from its serializable version
     * @param source the storable response
     * @param keys the information for signing
     * @return the native response object
     * @throws Exception error case
     */



    public static OCSPResponse transferToOCSPResponse(OCSPRespToStore source,
    Tuple<PrivateKey,
            X509Certificate[]> keys) throws Exception {
        BasicOCSPResponse basicResp = new BasicOCSPResponse();
        X509Certificate certificate = new X509Certificate(source.getCertEncoded());
        CertID id = new CertID(AlgorithmID.sha256,
                (Name) certificate.getIssuerDN(),
                certificate.getPublicKey(),
                certificate.getSerialNumber());
        ReqCert reqCert = new ReqCert(ReqCert.certID, id);

        CertStatus status = null;
        if (source.getStatus().equals(RespStatus.GOOD)) {
            status = new CertStatus();
        } else if (source.getStatus().equals(RespStatus.REVOKED)) {
            status = new CertStatus(new RevokedInfo(new Date()));
        } else {
            status = new CertStatus(new UnknownInfo());
        }
        SingleResponse single = new SingleResponse(reqCert, status, new Date());
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.YEAR, 1);
        Date date = new Date();
        date.setTime(cal.getTimeInMillis());
        single.setArchiveCutoff(date);
        SingleResponse[] responses = new SingleResponse[1];
        responses[0] = single;
        basicResp.setSingleResponses(responses);
        ResponderID responderID = new ResponderID(certificate.getPublicKey());
        basicResp.setResponderID(responderID);
        basicResp.setProducedAt(new Date());
        X509Certificate[] certs = new X509Certificate[0];
        if (source.getSignerCertEncoded() != null) {
            certs = new X509Certificate[2];
            certs[0] = new X509Certificate(source.getSignerCertEncoded());
            certs[1] = certificate;
        } else {
            certs = new X509Certificate[1];
            certs[0] = certificate;
        }
        basicResp.setCertificates(certs);
        OCSPResponse response = new OCSPResponse(basicResp);
        basicResp.sign(AlgorithmID.sha256WithRSAEncryption, keys.getFirst());

        return response;
    }

    /**
     * Class representing the response - status
     */
    public static enum RespStatus implements Serializable {
        GOOD(0),
        REVOKED(1),
        UNKNOWN(2);

        final int status;

        RespStatus(int status) {
            this.status = status;
        }

        public static RespStatus getByStatus(int stat) {
            for (RespStatus status: RespStatus.values()) {
                if (status.status == stat) {
                    return status;
                }
            }
            return RespStatus.GOOD;
        }
    }

    public static class LocalCache {
        private List<X509Certificate> certificateList = new ArrayList<>();

        private Map<BigInteger, Tuple<Date, OCSPRespToStore>> preparedResponses = new HashMap<>();

        public LocalCache() {
            certificateList =  new ArrayList<>();
            preparedResponses = new HashMap<>();
        }
        public List<X509Certificate> getCertificateList() {
            return certificateList;
        }

        public LocalCache setCertificateList(List<X509Certificate> chainList) {
            this.certificateList = chainList;
            return this;
        }

        public Map<BigInteger, Tuple<Date, OCSPRespToStore>> getPreparedResponses() {
            return preparedResponses;
        }

        public LocalCache setPreparedResponses(Map<BigInteger, Tuple<Date, OCSPRespToStore>> preparedResponses) {
            this.preparedResponses = preparedResponses;
            return this;
        }
    }

    /**
     * Class representing a serializable version of a O'CSPResponse object
     */
    public static class OCSPRespToStore implements Serializable {
        private RespStatus status;
        private int respCode = 0;
        private BigInteger serial;
        private byte[] certEncoded;
        private byte[] signerCertEncoded;
        public OCSPRespToStore(OCSPResponse response, BigInteger serial) throws Exception {
            try {
                Logger.trace("Step 1");
                BasicOCSPResponse basicResp = (BasicOCSPResponse)response.getResponse();
                Logger.trace("Step 2");
                int status = 0;
                if (basicResp != null) {
                    SingleResponse singleResponse = basicResp.getSingleResponses()[0];
                    if (singleResponse != null) {
                        Logger.trace("Step 3");
                        status = singleResponse.getCertStatus().getCertStatus();
                        Logger.trace("Step 4");
                        certEncoded = basicResp.getCertificates()[0].getEncoded();
                    }
                    Logger.trace("Step 5");
                    this.status = RespStatus.getByStatus(status);
                    Logger.trace("Step 6");
                    respCode = response.getResponseStatus();
                    Logger.trace("Step 7");
                    if (basicResp.getCertificates() != null && basicResp.getCertificates().length >= 1) {
                        signerCertEncoded = basicResp.getCertificates()[0].getEncoded();
                    }
                    Logger.trace("Step 8");
                }
                this.serial = serial;

            } catch(Exception ex) {
                Logger.trace("Construction of serializable failed"
                        + ex.getMessage() + " type "
                        + ex.getClass().getCanonicalName());
                throw new IllegalStateException("Construction of serializable failed", ex);
            }
        }

        public RespStatus getStatus() {
            return status;
        }

        public int getRespCode() {
            return respCode;
        }

        public BigInteger getSerial() {
            return serial;
        }

        public byte[] getCertEncoded() {
            return certEncoded;
        }

        public byte[] getSignerCertEncoded() {
            return signerCertEncoded;
        }
    }
}
