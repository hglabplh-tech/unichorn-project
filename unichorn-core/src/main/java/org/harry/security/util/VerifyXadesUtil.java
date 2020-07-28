package org.harry.security.util;

import iaik.asn1.CodingException;
import iaik.cms.CMSParsingException;
import iaik.security.provider.IAIKMD;
import iaik.x509.X509Certificate;
import iaik.x509.attr.AttributeCertificate;
import iaik.x509.ocsp.OCSPResponse;
import iaik.xml.crypto.XSecProvider;
import iaik.xml.crypto.utils.KeySelectorImpl;
import iaik.xml.crypto.xades.*;
import iaik.xml.crypto.xades.timestamp.TSPTimeStampToken;
import iaik.xml.crypto.xades.timestamp.TimeStampToken;
import iaik.xml.crypto.xades.timestamp.TimeStampTokenException;
import org.harry.security.util.algoritms.XAdESDigestAlg;
import org.harry.security.util.algoritms.XAdESSigAlg;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.trustlist.TrustListManager;
import org.pmw.tinylog.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

public class VerifyXadesUtil {

    /**
     * This is the list of trust-lists provided by EU to check the path of the signers certificate
     */
    private final List<TrustListManager> walkers;

    private final SigningBean bean;

    private final AlgorithmPathChecker algPathChecker;

    private final TimestampChecker tstChecker;

    private final Provider xSecProvider;

    private CertID sigCert;

    private CertIDV2 sigCertV2;

    private boolean ocspCheckDone = false;


    private List<X509Certificate> certList = new ArrayList<>();

    /**
     * The default constructor for verification
     * @param walkers the trust lists
     */
    public VerifyXadesUtil(List<TrustListManager> walkers, SigningBean bean) {
        this.walkers = walkers;
        this.bean = bean;
        this.algPathChecker = new AlgorithmPathChecker(walkers, bean);
        this.tstChecker = new TimestampChecker(walkers, bean);

        IAIKMD.addAsProvider();
        xSecProvider = new XSecProvider();
        Security.insertProviderAt(xSecProvider, 3);
        //move other XMLDsig provider to the end
        Provider otherXMLDsigProvider = Security.getProvider("XMLDSig");
        if (otherXMLDsigProvider != null) {
            Security.removeProvider(otherXMLDsigProvider.getName());
            Security.addProvider(otherXMLDsigProvider);
        }

    }

    public VerificationResults.VerifierResult verifyXadesSignature(InputStream sigStream, InputStream data) {
        try {
            VerificationResults.VerifierResult result = new VerificationResults.VerifierResult();
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            dbf.setIgnoringElementContentWhitespace(true);
            dbf.setExpandEntityReferences(false);
            dbf.setValidating(true);
            String schemaFile = "/xsd/xmldsig-core-schema.xsd";
            URL schemaURL = VerifyXadesUtil.class.getResource(schemaFile);
            dbf.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaLanguage",
                    "http://www.w3.org/2001/XMLSchema");
            dbf.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaSource", schemaURL.toExternalForm());
            dbf.setAttribute("http://apache.org/xml/features/validation/schema/normalized-value",
                    Boolean.FALSE);
            // parse the signature document
            Document doc = dbf.newDocumentBuilder().parse(sigStream);
            // Find Signature element
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (nl.getLength() == 0) {
                throw new Exception("Cannot find Signature element");
            }
            XMLSignatureFactory sfac = XMLSignatureFactory.getInstance("DOM", xSecProvider);
            QualifyingPropertiesFactory qfac = QualifyingPropertiesFactory.getInstance("DOM",
                    xSecProvider);

            // Create a DOMValidateContext and specify a KeyValue KeySelector
            // and document context
            DOMValidateContext valContext = new DOMValidateContext(new KeySelectorImpl(),
                    nl.item(0));
            valContext.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
            // unmarshal the XMLSignature
            XMLSignature signature = sfac.unmarshalXMLSignature(valContext);
            VerificationResults.SignerInfoCheckResults signerResult = new VerificationResults.SignerInfoCheckResults();



            // Validate the XMLSignature (generated above)
            boolean coreValidity = signature.validate(valContext);
            if (coreValidity) {
                // Look for a SignaturTimeStamp and SigningCertificate

                QualifyingProperties qp = ((XAdESSignature) signature).getQualifyingProperties();
                if (qp != null) {
                    UnsignedProperties up = qp.getUnsignedProperties();
                    SignedProperties sp = qp.getSignedProperties();

                    getCertificateV1(result, signerResult, sp);
                    canonMethodCheck(signature, signerResult);
                    collectCertChain(signature, signerResult);
                    checkRevocationInfo(valContext, up, signerResult);
                    checkCertificate(signerResult);
                    checkSignerRole(valContext,sp,
                            signerResult);
                    checkTimestamps(valContext, up, signerResult);
                    checkCounterSignature(valContext, up, result, signerResult);
                }
            } else {
                result.addSignersInfo("N/A", signerResult);
                signerResult.addSignatureResult("sigMathOk", new Tuple<>("signature math ok",
                        VerificationResults.Outcome.FAILED));
            }
            return result;
        } catch(Exception ex) {
            throw new IllegalStateException("verification failed", ex);
        }


    }

    private void collectCertChain(XMLSignature signature, VerificationResults.SignerInfoCheckResults signerResult) {
        certList.clear();
        SignatureMethod sigMeth = signature.getSignedInfo().getSignatureMethod();
        List<Reference> refs = signature.getSignedInfo().getReferences();
        DigestMethod digestMeth = refs.get(0).getDigestMethod();
        XAdESSigAlg sigAlg = XAdESSigAlg.getByName(sigMeth.getAlgorithm());
        XAdESDigestAlg digestAlg = XAdESDigestAlg.getByName(digestMeth.getAlgorithm());
        KeyInfo keyInfo = signature.getKeyInfo();
        for (Object certData : keyInfo.getContent()) {
            X509Data x509Data = (X509Data)certData;
            for (Object obj: x509Data.getContent()) {
                X509Certificate iaikCert = (X509Certificate)obj;
                this.certList.add(iaikCert);
            }
        }
        X509Certificate [] chain = new X509Certificate[certList.size()];
        for (int index = 0;index < chain.length;index++) {
            chain[index] = certList.get(index);
        }

        try {
            signerResult.addSignatureResult("sigAlg",
                    new Tuple<>(sigAlg.getAlgorithm().getImplementationName(), VerificationResults.Outcome.SUCCESS));
            signerResult.addSignatureResult("digestAlg",
                    new Tuple<>(digestAlg.getAlgorithm().getImplementationName(), VerificationResults.Outcome.SUCCESS));
            algPathChecker.checkSignatureAlgorithm(sigAlg.getAlgorithm(), chain[0].getPublicKey(), signerResult);
        } catch (Exception ex) {
            Logger.trace("algorithm detection failes" + ex.getMessage());
            Logger.trace(ex);
            throw new IllegalStateException("algorithm detection failes" + ex.getMessage(), ex);
        }
    }

    private void canonMethodCheck(XMLSignature signature, VerificationResults.SignerInfoCheckResults signerResult) {
        CanonicalizationMethod method = signature.getSignedInfo().getCanonicalizationMethod();
        if (method.getAlgorithm().equals(CanonicalizationMethod.INCLUSIVE)
                || method.getAlgorithm().equals(CanonicalizationMethod.EXCLUSIVE)) {
            signerResult.addSignatureResult("canon method check",
                    new Tuple<>("canon method checked ok", VerificationResults.Outcome.SUCCESS));
        } else {
            signerResult.addSignatureResult("canon method check",
                    new Tuple<>("canon method checked NOT ok", VerificationResults.Outcome.FAILED));
        }
    }

    private void checkCertificate( VerificationResults.SignerInfoCheckResults signerResult) {
        BigInteger serialNumber = null;
       if (sigCert != null ) {
           IssuerSerial serial = sigCert.getIssuerSerial();
           serialNumber = serial.getSerialNumber();
       } else if (sigCertV2 != null) {
           IssuerSerialV2 serial = sigCertV2.getIssuerSerialV2();
           serialNumber = serial.getSerialNumber();
       }

       if (serialNumber != null) {
           BigInteger finalSerialNumber = serialNumber;
           Optional<X509Certificate> certificate =
                   certList.stream()
                           .filter(e -> e.getSerialNumber().equals(finalSerialNumber))
                           .findFirst();
           if (certificate.isPresent()) {
               Logger.trace("Signing cert found subject is: " + certificate.get().getSubjectDN().getName());
               SigningBean bean = new SigningBean().setCheckPathOcsp(!this.ocspCheckDone);
               AlgorithmPathChecker checker =
                       new AlgorithmPathChecker(ConfigReader.loadAllTrusts(), bean);
               X509Certificate [] chain = checker.detectChain(certificate.get(), null, signerResult);

           }
       }
    }

    private void checkRevocationInfo(DOMValidateContext valContext, UnsignedProperties up,
                                     VerificationResults.SignerInfoCheckResults signerResult) {
        try {
            if (up != null) {
                UnsignedSignatureProperties usp = up.getUnsignedSignatureProperties();
                if (usp != null) {
                    CompleteRevocationRefs revocatioRefs = usp.getCompleteRevocationRefs();
                    if (revocatioRefs != null) {
                        List<OCSPRef> refs = revocatioRefs.getOCSPRefs();
                        for (OCSPRef obj : refs) {
                            Logger.trace("Object class of ref is: " + obj.getClass().getCanonicalName());
                            Logger.trace(obj.getOCSPIdentifier().getURI());
                            Logger.trace(obj.getOCSPIdentifier().getResponderId().byName());
                            Logger.trace(obj.getOCSPIdentifier().getProducedAt().toString());
                            DigestAlgAndValue digestData = obj.getDigestAlgAndValue();
                            boolean check = obj.validate(valContext, null);
                            System.out.println("Check result is: " + check);
                            this.ocspCheckDone = true;
                            if (check) {
                                String uriString = obj.getOCSPIdentifier().getURI();
                                URI uri = new URI(uriString);
                                File respFile = new File(uri);
                                OCSPResponse response = new OCSPResponse(new FileInputStream(respFile));
                                signerResult.addOcspResult("ocspResult",
                                        new Tuple<OCSPResponse, VerificationResults.Outcome>(response, VerificationResults.Outcome.SUCCESS));
                            } else {
                                signerResult.addOcspResult("ocspResult",
                                        new Tuple<OCSPResponse, VerificationResults.Outcome>(null, VerificationResults.Outcome.FAILED));
                            }
                        }
                    } else {

                    }
                }
            }
        } catch (Exception ex) {
            Logger.trace("ocsp check hard failure: " + ex.getMessage());
            Logger.trace(ex);
            throw new IllegalStateException("ocsp check hard failure", ex);
        }
    }

    private void checkCounterSignature(DOMValidateContext valContext, UnsignedProperties up,
                                     VerificationResults.VerifierResult result,
                                     VerificationResults.SignerInfoCheckResults signerResult) {
        try {
            this.ocspCheckDone = false;
            UnsignedSignatureProperties usp = up.getUnsignedSignatureProperties();
            if (usp != null) {
                List<CounterSignature> counterSigs = usp.getCounterSignatures();
                if (counterSigs != null) {
                    for (CounterSignature counterSignature : counterSigs) {
                        XMLSignature signature = counterSignature.getSignature();
                        if (signature != null) {
                            boolean success = signature.validate(valContext);
                            if (success) {
                                signerResult.addSignatureResult("counter signature",
                                        new Tuple<>("valid signature found", VerificationResults.Outcome.SUCCESS));
                                QualifyingProperties qp = ((XAdESSignature) signature).getQualifyingProperties();
                                signerResult = new VerificationResults.SignerInfoCheckResults();
                                if (qp != null) {
                                    up = qp.getUnsignedProperties();
                                    SignedProperties sp = qp.getSignedProperties();
                                    getCertificateV1(result, signerResult, sp);
                                    collectCertChain(signature, signerResult);
                                    checkRevocationInfo(valContext, up, signerResult);
                                    checkCertificate(signerResult);

                                }
                            } else {
                                signerResult.addSignatureResult("counter signature",
                                        new Tuple<>("NOT valid signature found", VerificationResults.Outcome.FAILED));
                            }
                        } else {
                            signerResult.addSignatureResult("counter signature",
                                    new Tuple<>("none signature found", VerificationResults.Outcome.INDETERMINED));
                        }
                    }
                } else {

                }
            }
        } catch (Exception ex) {
            Logger.trace("ocsp check hard failure: " + ex.getMessage());
            Logger.trace(ex);
            throw new IllegalStateException("ocsp check hard failure", ex);
        }
    }

    private void checkSignerRole(DOMValidateContext valContext,SignedProperties sp,
                                       VerificationResults.SignerInfoCheckResults signerResult) {
        try {
            this.ocspCheckDone = false;
            SignedSignatureProperties ssp = sp.getSignedSignatureProperties();
            if (ssp != null) {
                SignatureProductionPlaceV2 place = ssp.getSignatureProductionPlaceV2();
                if (place != null) {
                    VerificationResults.ProdPlace prodPlace = new VerificationResults.ProdPlace()
                            .setCity(place.getCity())
                            .setCountry(place.getCountryName())
                            .setRegion(place.getStateOrProvince())
                            .setStreet(place.getStreetAddress())
                            .setZipCode(place.getPostalCode());
                    signerResult.setProdPlace(prodPlace);

                }
                SignerRoleV2 roles = ssp.getSignerRoleV2();
                if (roles != null) {
                        for (Object object : roles.getCertifiedRoles()) {
                            CertifiedRoleV2 role = (CertifiedRoleV2)object;
                            X509AttributeCertificate attr = role.getX509AttributeCertificate();
                            AttributeCertificate cert = new AttributeCertificate(attr.getAttributeCertificate());
                            try {
                               // cert.verify(certList.get(0).getPublicKey());
                                signerResult.addSignatureResult("attrCertCheck"
                                        , new Tuple<>("attribute cert ok", VerificationResults.Outcome.SUCCESS));
                                signerResult.setAttrCert(cert);
                            } catch (Exception ex) {
                                Logger.trace("Attr cert verify exception: " + ex.getMessage());
                                Logger.trace(ex);
                                signerResult.addSignatureResult("attrCertCheck"
                                        , new Tuple<>("attribute cert NOT ok", VerificationResults.Outcome.FAILED));
                            }
                        }
                } else {
                    signerResult.addSignatureResult("attrCert"
                            , new Tuple<>("attribute cert ok", VerificationResults.Outcome.INDETERMINED));
                }
            }
        } catch (Exception ex) {
            Logger.trace("attribute cert check hard failure: " + ex.getMessage());
            Logger.trace(ex);
            throw new IllegalStateException("attribute cert check hard failure: ", ex);
        }
    }



    private void checkTimestamps(DOMValidateContext valContext, UnsignedProperties up, VerificationResults.SignerInfoCheckResults signerResult) throws XMLSignatureException, TimeStampTokenException, CMSParsingException, CodingException, CertificateException, NoSuchAlgorithmException {
        if (up != null) {
            UnsignedSignatureProperties usp = up.getUnsignedSignatureProperties();
            if (usp != null) {
                SignatureTimeStamp sigTS = null;
                List sigTSs = usp.getSignatureTimeStamps();
                if (!sigTSs.isEmpty()) {
                    sigTS = (SignatureTimeStamp) sigTSs.get(0);
                    Date validationDate;
                    boolean tsValid = sigTS.validate(valContext);
                    if (tsValid) {
                        TimeStampToken tsToken = sigTS.getTimeStampToken();
                        validationDate = tsToken.getTime();

                        signerResult.addSignatureResult("timestamp check",
                                new Tuple<>("timstamp is ok: " + validationDate.toString(), VerificationResults.Outcome.SUCCESS));
                        if (tsToken instanceof TSPTimeStampToken) {
                            TSPTimeStampToken token = (TSPTimeStampToken)tsToken;
                            tstChecker.checkAnyTimestamp(new iaik.tsp.TimeStampToken(token.getDEREncoded()), "signature timestamp", signerResult);
                        }
                        System.out.println("timestamp signature valid.");
                    } else {
                        signerResult.addSignatureResult("timestamp check",
                                new Tuple<>("timstamp is NOT ok", VerificationResults.Outcome.FAILED));

                    }
                }
            }
        }
    }

    private void getCertificateV1(VerificationResults.VerifierResult result, VerificationResults.SignerInfoCheckResults signerResult, SignedProperties sp) {
        if (sp != null) {
            SignedSignatureProperties ssp = sp.getSignedSignatureProperties();
            if (ssp != null) {
                SigningCertificate sigCerts = ssp.getSigningCertificate();
                if (sigCerts != null) {
                    List certs = sigCerts.getCertIDs();
                    if (!certs.isEmpty()) {
                        sigCert = (CertID) certs.get(0);
                        result.addSignersInfo(UUID.randomUUID().toString(), signerResult);
                        signerResult.addSignatureResult("sigMathOk", new Tuple<>("signature math ok",
                                VerificationResults.Outcome.SUCCESS));
                    }
                } else {
                    getCertificateV2(result, signerResult, sp);
                }
            }
        }
    }

    private void getCertificateV2(VerificationResults.VerifierResult result, VerificationResults.SignerInfoCheckResults signerResult, SignedProperties sp) {
        if (sp != null) {
            SignedSignatureProperties ssp = sp.getSignedSignatureProperties();
            if (ssp != null) {
                SigningCertificateV2 sigCerts = ssp.getSigningCertificateV2();
                if (sigCerts != null) {
                    List certs = sigCerts.getCertIDs();
                    if (!certs.isEmpty()) {
                        sigCertV2 = (CertIDV2) certs.get(0);
                        result.addSignersInfo(UUID.randomUUID().toString(), signerResult);
                        signerResult.addSignatureResult("sigMathOk", new Tuple<>("signature math ok",
                                VerificationResults.Outcome.SUCCESS));
                    }
                }
            }
        }
    }


}
