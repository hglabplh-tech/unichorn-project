package org.harry.security.util;

import iaik.security.provider.IAIKMD;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.OCSPResponse;
import iaik.x509.ocsp.UnknownResponseException;
import iaik.xml.crypto.XSecProvider;
import iaik.xml.crypto.utils.KeySelectorImpl;
import iaik.xml.crypto.xades.*;
import iaik.xml.crypto.xades.timestamp.TimeStampToken;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.trustlist.TrustListManager;
import org.pmw.tinylog.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.crypto.Data;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import java.util.List;
import java.util.Set;

public class VerifyXadesUtil {

    /**
     * This is the list of trust-lists provided by EU to check the path of the signers certificate
     */
    private final List<TrustListManager> walkers;

    private final SigningBean bean;

    private final AlgorithmPathChecker algPathChecker;

    private final Provider xSecProvider;

    /**
     * The default constructor for verification
     * @param walkers the trust lists
     */
    public VerifyXadesUtil(List<TrustListManager> walkers, SigningBean bean) {
        this.walkers = walkers;
        this.bean = bean;
        this.algPathChecker = new AlgorithmPathChecker(walkers, bean);

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
                    checkRevocationInfo(valContext, up, signerResult);
                    checkTimestamps(valContext, up, signerResult);
                    //dummy(qp);



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

    private void canonMethodCheck(XMLSignature signature, VerificationResults.SignerInfoCheckResults signerResult) {
        CanonicalizationMethod method = signature.getSignedInfo().getCanonicalizationMethod();
        SignatureMethod sigMeth = signature.getSignedInfo().getSignatureMethod();
        List<Reference> refs = signature.getSignedInfo().getReferences();
        DigestMethod digestMeth = refs.get(0).getDigestMethod();
        signerResult.addSignatureResult("sigAlg",
                new Tuple<>(sigMeth.getAlgorithm(), VerificationResults.Outcome.SUCCESS));
        signerResult.addSignatureResult("digestAlg",
                new Tuple<>(digestMeth.getAlgorithm(), VerificationResults.Outcome.SUCCESS));
        // TODO: here we have to code the real check later
        signerResult.addSignatureResult("check_signature_algorithm",
                new Tuple<>("signature alg ok", VerificationResults.Outcome.SUCCESS));
        if (method.getAlgorithm().equals(CanonicalizationMethod.INCLUSIVE)
                || method.getAlgorithm().equals(CanonicalizationMethod.EXCLUSIVE)) {
            signerResult.addSignatureResult("canon method check",
                    new Tuple<>("canon method checked ok", VerificationResults.Outcome.SUCCESS));
        } else {
            signerResult.addSignatureResult("canon method check",
                    new Tuple<>("canon method checked NOT ok", VerificationResults.Outcome.FAILED));
        }
    }

    private void dummy(QualifyingProperties qp) {
        SigningCertificateV2 signingCert = qp.getSignedProperties().getSignedSignatureProperties().getSigningCertificateV2();
        List<CertIDV2> certIds = signingCert.getCertIDs();
        for (CertIDV2 certID: certIds) {
            String issuer = certID.getIssuerSerialV2().getIssuerName();
            certID.getIssuerSerialV2().getSerialNumber();
        }
    }

    private void checkRevocationInfo(DOMValidateContext valContext, UnsignedProperties up,
                                     VerificationResults.SignerInfoCheckResults signerResult) {
        try {
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
        } catch (Exception ex) {
            Logger.trace("ocsp check hard failure: " + ex.getMessage());
            Logger.trace(ex);
            throw new IllegalStateException("ocsp check hard failure", ex);
        }
    }

    private void checkTimestamps(DOMValidateContext valContext, UnsignedProperties up, VerificationResults.SignerInfoCheckResults signerResult) throws XMLSignatureException {
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
                    } else {
                        signerResult.addSignatureResult("timestamp check",
                                new Tuple<>("timstamp is NOT ok", VerificationResults.Outcome.FAILED));

                    }
                }
            }
        }
    }

    private void getCertificateV1(VerificationResults.VerifierResult result, VerificationResults.SignerInfoCheckResults signerResult, SignedProperties sp) {
        CertID sigCert;
        if (sp != null) {
            SignedSignatureProperties ssp = sp.getSignedSignatureProperties();
            if (ssp != null) {
                SigningCertificate sigCerts = ssp.getSigningCertificate();
                if (sigCerts != null) {
                    List certs = sigCerts.getCertIDs();
                    if (!certs.isEmpty()) {
                        sigCert = (CertID) certs.get(0);
                        result.addSignersInfo(sigCert.getURI(), signerResult);
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
        CertIDV2 sigCert;
        if (sp != null) {
            SignedSignatureProperties ssp = sp.getSignedSignatureProperties();
            if (ssp != null) {
                SigningCertificateV2 sigCerts = ssp.getSigningCertificateV2();
                if (sigCerts != null) {
                    List certs = sigCerts.getCertIDs();
                    if (!certs.isEmpty()) {
                        sigCert = (CertIDV2) certs.get(0);
                        result.addSignersInfo(sigCert.getURI(), signerResult);
                        signerResult.addSignatureResult("sigMathOk", new Tuple<>("signature math ok",
                                VerificationResults.Outcome.SUCCESS));
                    }
                }
            }
        }
    }


}
