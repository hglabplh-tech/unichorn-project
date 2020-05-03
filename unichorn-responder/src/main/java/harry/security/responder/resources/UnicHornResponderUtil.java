package harry.security.responder.resources;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AccessDescription;
import iaik.asn1.structures.AlgorithmID;
import iaik.utils.ASN1InputStream;
import iaik.x509.RevokedCertificate;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.AuthorityInfoAccess;
import iaik.x509.extensions.ReasonCode;
import iaik.x509.ocsp.*;
import iaik.x509.ocsp.extensions.ServiceLocator;
import iaik.x509.ocsp.net.HttpOCSPRequest;
import iaik.x509.ocsp.utils.ResponseGenerator;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.trustlist.TrustListLoader;
import org.harry.security.util.trustlist.TrustListManager;
import org.pmw.tinylog.Logger;

import java.io.*;
import java.math.BigInteger;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.sql.Time;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

import static org.harry.security.util.CertificateWizzard.isCertificateSelfSigned;
import static org.harry.security.util.ocsp.HttpOCSPClient.getCRLOfCert;

public class UnicHornResponderUtil {

    public static String APP_DIR;

    public static String APP_DIR_TRUST;

    private static List<X509Certificate[]> chainList = new ArrayList<>();

    static {
        String userDir = System.getProperty("user.home");
        userDir = userDir + "\\AppData\\Local\\MySigningApp";
        File dir = new File(userDir);
        if (!dir.exists()) {
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
        loadActualPrivStore();
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
            signatureAlgorithm = AlgorithmID.sha1WithRSAEncryption;


        } catch (Exception ex) {
            messages.put("keysexcp", "IO keystore exception" + ex.getMessage() + " of Type: " + ex.getClass().getName());
        }
        //
        PrivateKey responderKey = responseGenerator.getResponderKey();

        signatureAlgorithm = getAlgorithmID(signatureAlgorithm, messages, responderKey);
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
        messages.put("info-2", "Message is: crl loaded");
        System.out.println("Create response entries for crl...");

        messages.put("info-3", "Message is: before add resp entries");
        OCSPResponse response = checkCertificateRevocation(ocspRequest, responseGenerator, messages, crl);


        try {
            if (response != null) {
                return response;
            } else {
                return getOcspResponse(ocspReqInput, responseGenerator, signatureAlgorithm, messages, keys);
            }
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

    private static OCSPResponse checkCertificateRevocation(OCSPRequest ocspRequest, ResponseGenerator responseGenerator, Map<String, String> messages, X509CRL crl) {
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
                ReqCert reqCert = req.getReqCert();
                if (reqCert.getType() == ReqCert.certID) {
                    CertID certID = (CertID) reqCert.getReqCert();
                    BigInteger serial = certID.getSerialNumber();
                    AlgorithmID hashAlg = certID.getHashAlgorithm();


                    Date rDate = checkRevocation(crl, serial);
                    X509Certificate actualCert = getX509Certificate(serial);
                    if (rDate == null && actualCert != null) {
                        setResponseEntry(responseGenerator, reqCert, null, actualCert);
                    } else if (actualCert == null && rDate == null) {
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(new UnknownInfo()), endDate, null);
                    } else {
                        if (crl.containsCertificate(serial) != null) {
                            X509CRLEntry entry = crl.getRevokedCertificate(serial);
                            CRLReason reason = entry.getRevocationReason();
                        }
                        RevokedInfo info = new RevokedInfo(rDate);
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(info), rDate, null);
                    }


                } else if (reqCert.getType() == ReqCert.pKCert) {
                    X509Certificate certificate = (X509Certificate) reqCert.getReqCert();
                    X509CRL crlToUse = null;
                    crlToUse = getCRLOfCert(certificate);
                    if (crlToUse == null) {
                        crlToUse = crl;
                    }

                    Date rDate = checkRevocation(crl, certificate.getSerialNumber());
                    X509Certificate actualCert = getX509Certificate(certificate.getSerialNumber());
                    if (rDate == null && actualCert != null) {
                        setResponseEntry(responseGenerator, reqCert, certificate, actualCert);
                    } else if (actualCert == null && rDate == null) {
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(new UnknownInfo()), endDate, null);
                    } else {
                        if (crl.containsCertificate(certificate.getSerialNumber()) != null) {
                            X509CRLEntry entry = crl.getRevokedCertificate(certificate.getSerialNumber());
                            CRLReason reason = entry.getRevocationReason();
                        }
                        RevokedInfo info = new RevokedInfo(rDate);
                        responseGenerator.addResponseEntry(reqCert, new CertStatus(info), rDate, null);
                    }
                }
            }
            messages.put("info-4", "Message is: generator created");
            System.out.println("Generator created:");
            System.out.println(responseGenerator);
            return null;
        } catch (Exception ex) {
            messages.put("err-gen", "Message is: generator is NOT created due to: " + ex.getMessage());
            return null;
        }
    }

    private static void setResponseEntry(ResponseGenerator responseGenerator, ReqCert reqCert, X509Certificate certificate, X509Certificate actualCert) throws OCSPException {
        Optional<X509Certificate> issuer = findIssuer(actualCert);
        boolean matches = false;
        boolean error = false;
        try {
            if (isCertificateSelfSigned(actualCert)) {
                responseGenerator.addResponseEntry(reqCert, new CertStatus(new UnknownInfo()), actualCert.getNotAfter(), null);
            }
            actualCert.checkValidity();
        } catch (CertificateExpiredException e) {
            error = true;
        } catch (CertificateNotYetValidException e) {
            error = true;
        }
        if (issuer.isPresent()) {
            matches = reqCert.isReqCertFor(actualCert, issuer.get(), null);
        } else {
            matches = false;
        }
        if (matches && !error) {
            if (certificate != null) {
                responseGenerator.addResponseEntry(reqCert, new CertStatus(), certificate.getNotAfter(), null);
            } else {
                responseGenerator.addResponseEntry(reqCert, new CertStatus(), actualCert.getNotAfter(), null);
            }
        } else if (!error) {
            if (certificate != null) {
                responseGenerator.addResponseEntry(reqCert, new CertStatus(new UnknownInfo()), certificate.getNotAfter(), null);
            } else {
                responseGenerator.addResponseEntry(reqCert, new CertStatus(new UnknownInfo()), actualCert.getNotAfter(), null);
            }
        } else {
            Calendar cal = Calendar.getInstance();
            RevokedInfo info = new RevokedInfo(new Date(cal.getTimeInMillis()));
            info.setRevocationReason(new ReasonCode(ReasonCode.privilegeWithdrawn));
            if (certificate != null) {
                responseGenerator.addResponseEntry(reqCert, new CertStatus(info), certificate.getNotAfter(), null);
            } else {
                responseGenerator.addResponseEntry(reqCert, new CertStatus(info), actualCert.getNotAfter(), null);
            }
        }
    }

    private static X509Certificate getX509Certificate(BigInteger serial) {
        Optional<X509Certificate[]> found = findSerialINPositiveList(serial);
        X509Certificate actualCert = null;
        if (found.isPresent()) {
            for (X509Certificate cert : found.get()) {
                if (cert.getSerialNumber().equals(serial)) {
                    actualCert = cert;
                }
            }

        }
        return actualCert;
    }

    private static AlgorithmID getAlgorithmID(AlgorithmID signatureAlgorithm, Map<String, String> messages, PrivateKey responderKey) {
        if (!(responderKey instanceof java.security.interfaces.RSAPrivateKey)) {
            if (responderKey instanceof java.security.interfaces.DSAPrivateKey) {
                signatureAlgorithm = AlgorithmID.dsaWithSHA1;
            } else {
                signatureAlgorithm = AlgorithmID.sha1WithRSAEncryption;
            }
        }
        try {
            messages.put("info-1", "Message is:" + signatureAlgorithm.getImplementationName());
        } catch (Exception ex) {

        }
        return signatureAlgorithm;
    }

    private static Tuple<PrivateKey, X509Certificate[]> getPrivateKeyX509CertificateTuple() {
        Tuple<PrivateKey, X509Certificate[]> keys = null;
        InputStream keyStore = UnicHornResponderUtil.class.getResourceAsStream("/application.p12");
        KeyStore store = KeyStoreTool.loadStore(keyStore, "geheim".toCharArray(), "PKCS12");
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
     * @param is the name of the crl file
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

    public static void loadActualPrivStore() {
        chainList = new ArrayList<>();
        loadActualPrivTrust();
        try {
            File keyFile = new File(UnicHornResponderUtil.APP_DIR_TRUST, "privKeystore" + ".jks");
            KeyStore storeApp = KeyStoreTool.loadStore(new FileInputStream(keyFile), null, "PKCS12");
            Enumeration<String> aliasEnum = storeApp.aliases();
            while (aliasEnum.hasMoreElements()) {
                String alias = aliasEnum.nextElement();
                X509Certificate[] chain = KeyStoreTool.getCertChainEntry(storeApp, alias);
                chainList.add(chain);
            }
        } catch (Exception ex) {
            throw new IllegalStateException("not loaded keys", ex);
        }
    }

    public static void loadActualPrivTrust() {
        try {
            File trustFile = new File(UnicHornResponderUtil.APP_DIR_TRUST, "trustListPrivate" + ".xml");
            TrustListLoader loader = new TrustListLoader();
            if (trustFile.exists()) {
                TrustListManager manager = loader.getManager(trustFile);
                X509Certificate[] array = manager.getAllCerts()
                        .toArray(new X509Certificate[manager.getAllCerts().size()]);
                chainList.add(array);
            }
        } catch (Exception ex) {
            throw new IllegalStateException("not loaded keys", ex);
        }
    }


    public static InputStream loadActualCRL() {
        File crlFile = new File(UnicHornResponderUtil.APP_DIR_TRUST, "privRevokation" + ".crl");
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

    private static Date checkRevocation(X509CRL crl, BigInteger certSerial) {
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

    private static Optional<X509Certificate[]> findSerialINPositiveList(BigInteger serial) {
        Optional<X509Certificate[]> opt = chainList.stream().filter(e -> {
            for (X509Certificate cert : e) {
                if (cert.getSerialNumber().equals(serial)) {
                    return true;
                }
            }
            return false;
        }).findFirst();
        return opt;
    }

    private static Optional<X509Certificate> findIssuer(X509Certificate actualCert) {
        AtomicReference<Optional<X509Certificate>> optIssuer = new AtomicReference<>(Optional.empty());
        Optional<X509Certificate[]> opt = chainList.stream().filter(e -> {
            for (X509Certificate cert : e) {
                if (actualCert.getIssuerDN().getName().equals(cert.getSubjectDN().getName())) {
                    optIssuer.set(Optional.of(cert));
                    return true;
                }
            }
            return false;
        }).findFirst();
        return optIssuer.get();
    }

    public static void applyKeyStore(File keyFile, KeyStore storeToApply, String passwd, String storeType) {
        try {
            ExecutorService executor = Executors.newFixedThreadPool(5);
            Future<?> task = executor.submit(new WorkerThread(keyFile, storeToApply, passwd, storeType));
            task.get(10, TimeUnit.MINUTES);
            executor.shutdown();
        } catch (Exception ex) {
            Logger.trace("thread failed with:" + ex.getMessage());
            throw new IllegalStateException("thread failed with:", ex);
        }

    }
}
