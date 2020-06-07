package org.harry.security.util;

import iaik.asn1.ObjectID;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.X509ExtensionInitException;
import iaik.x509.extensions.ExtendedKeyUsage;
import iaik.x509.extensions.KeyUsage;
import no.difi.xsd.asic.model._1.Certificate;
import oasis.names.tc.dss._1_0.core.schema.*;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.*;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ObjectFactory;
import oasis.names.tc.opendocument.xmlns.manifest._1.Algorithm;
import org.etsi.uri._01903.v1_3.IdentifierType;
import org.etsi.uri._01903.v1_3.ObjectIdentifierType;
import org.etsi.uri._01903.v1_3.QualifierType;


import javax.xml.bind.JAXBElement;
import javax.xml.registry.infomodel.InternationalString;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class VerifyReporter {

    public static final String MAJORCODE_PASS = "urn:oasis:names:tc:dss:1.0:detail:valid";

    public static final String MAJORCODE_FAIL = "urn:oasis:names:tc:dss:1.0:detail:invalid";

    public static final String MAJORCODE_NA = "urn:oasis:names:tc:dss:1.0:detail:indetermined";


    private final VerificationReportType report;
    private final IndividualReportType individualReport;
    private final VerifyUtil.VerifierResult checkResult;
    private final List<VerifyUtil.SignerInfoCheckResults> infoResult;
    private List<JAXBElement<DetailedSignatureReportType>> detailList;



    public VerifyReporter(VerifyUtil.VerifierResult checkResult) {
        this.checkResult = checkResult;
        this.infoResult = checkResult.getSignersCheck();
        ReturnVerificationReport reportSettings = new ReturnVerificationReport();
        report = new VerificationReportType();
        ObjectFactory factory = new ObjectFactory();
        individualReport = factory.createIndividualReportType();
        report.getIndividualReport().add(individualReport);
        Result reportResult = new Result();
        VerifyUtil.Outcome outcome = VerifyUtil.Outcome.SUCCESS;
        for (VerifyUtil.SignerInfoCheckResults sigCheckResult : infoResult) {
            VerifyUtil.Outcome subResult = sigCheckResult.checkOverallResult();
            if (subResult == VerifyUtil.Outcome.FAILED) {
                outcome = VerifyUtil.Outcome.FAILED;
            }
        }
        String resultMajor;
        if (outcome == VerifyUtil.Outcome.SUCCESS) {
            resultMajor = MAJORCODE_PASS;
        } else {
            resultMajor = MAJORCODE_FAIL;
        }
        VerificationResultType verResult = generateVerificationResult(resultMajor, "overall report result");
        reportResult.setResultMajor(verResult.getResultMajor());
        reportResult.setResultMessage(verResult.getResultMessage());
        individualReport.setResult(reportResult);


    }

    public VerificationReportType generateReport() throws Exception {
        report.getIndividualReport().add(individualReport);
        detailList = generateSignatureReport();
        List<JAXBElement<OCSPValidityType>> ocspList = generateOcspReport();
        AnyType detail = new AnyType();
        detail.getAny().addAll(detailList);
        detail.getAny().addAll(ocspList);
        individualReport.setDetails(detail);
        return report;
    }

    public List<JAXBElement<OCSPValidityType>> generateOcspReport() {
        List<JAXBElement<OCSPValidityType>> ocspResultList = new ArrayList<>();
        ObjectFactory factory = new ObjectFactory();
        for (VerifyUtil.SignerInfoCheckResults results : infoResult) {
            OCSPValidityType ocspResult = factory.createOCSPValidityType();
            JAXBElement<OCSPValidityType> element = factory.createIndividualOCSPReport(ocspResult);
            OCSPContentType.Responses responses = factory.createOCSPContentTypeResponses();
            SingleResponseType singleResp = factory.createSingleResponseType();
            Tuple<String, VerifyUtil.Outcome> ocsp = results.getOCSPResult();
            String resultMajor;
            String message;
            if (ocsp != null) {
                if (ocsp.getSecond() == VerifyUtil.Outcome.SUCCESS)  {
                    resultMajor = MAJORCODE_PASS;
                    message = ocsp.getFirst();
                } else {
                    resultMajor = MAJORCODE_FAIL;
                    message = "ocsp request failed";
                }
            } else {
                resultMajor = MAJORCODE_NA;
                message = "ocsp check result N/A";
            }
            VerificationResultType result = generateVerificationResult(resultMajor, message);
            singleResp.setCertStatus(result);
            responses.getSingleResponse().add(singleResp);
            OCSPContentType content = factory.createOCSPContentType(); // todo place real response in result
            content.setResponses(responses);
            ocspResult.setOCSPContent(content);
            ocspResultList.add(element);
        }
        return ocspResultList;


    }

    public List<JAXBElement<DetailedSignatureReportType>> generateSignatureReport() throws Exception {
        ObjectFactory factory = new ObjectFactory();
        List<JAXBElement<DetailedSignatureReportType>> detailReportList = new ArrayList<>();
        for (VerifyUtil.SignerInfoCheckResults results : infoResult) {
            DetailedSignatureReportType signatureReport = new DetailedSignatureReportType();
            JAXBElement<DetailedSignatureReportType> element = factory.createDetailedSignatureReport(signatureReport);
            VerifyUtil.Outcome outcome = results.checkFormatResult();
            String resultMajor;
            String message;
            if (outcome == VerifyUtil.Outcome.SUCCESS) {
                resultMajor = MAJORCODE_PASS;
                message = "format results are all ok";
            } else {
                resultMajor = MAJORCODE_FAIL;
                message = "even one format result has status failed";
            }
            VerificationResultType result = generateVerificationResult(resultMajor, message);
            signatureReport.setFormatOK(result);
            SignatureValidityType signatureValid = factory.createSignatureValidityType();
            outcome = results.sigMathOk();
            if (outcome == VerifyUtil.Outcome.SUCCESS) {
                resultMajor = MAJORCODE_PASS;
                message = "signature is mathematically correct";
            } else {
                resultMajor = MAJORCODE_FAIL;
                message = "signature is mathematically incorrect";
            }
            result = generateVerificationResult(resultMajor, message);
            signatureValid.setSigMathOK(result);
            Tuple<String, VerifyUtil.Outcome> sigAlg = results.getSignatureAlgorithm();
            if (sigAlg != null) {
                AlgorithmValidityType algValid = factory.createAlgorithmValidityType();
                algValid.setAlgorithm(sigAlg.getFirst());
                if (sigAlg.getSecond() == VerifyUtil.Outcome.SUCCESS) {
                    resultMajor = MAJORCODE_PASS;
                    message = "signature algorithm is ok";
                } else if (sigAlg.getSecond() == VerifyUtil.Outcome.INDETERMINED) {
                    resultMajor = MAJORCODE_NA;
                    message = "signature algorithm is not clear state";
                } else {
                    resultMajor = MAJORCODE_FAIL;
                    message = "signature algorithm is not ok";
                }
                result = generateVerificationResult(resultMajor, message);
                algValid.setSuitability(result);
                signatureValid.setSignatureAlgorithm(algValid);
            }
            signatureReport.setSignatureOK(signatureValid);
            CertificatePathValidityType pathValidity = new CertificatePathValidityType();
            X509Certificate[] chain = results.getSignerChain();
            if (chain != null && chain.length > 1) {
                resultMajor = MAJORCODE_PASS;
                message = "certificate chain correct";
            } else {
                resultMajor = MAJORCODE_FAIL;
                message = "certificate chain incorrect";
            }
            result = generateVerificationResult(resultMajor, message);
            pathValidity.setPathValiditySummary(result);
            CertificatePathValidityVerificationDetailType detail = new CertificatePathValidityVerificationDetailType();
            List<CertificateValidityType> detailList = detail.getCertificateValidity();
            for (X509Certificate cert : chain) {
                CertificateValidityType detailResult = new CertificateValidityType();
                CertificateContentType certContent = generateCertificateContent(cert);

                detailResult.setCertificateContent(certContent);

                detailList.add(detailResult);
            }
            pathValidity.setPathValidityDetail(detail);
            signatureReport.setCertificatePathValidity(pathValidity);

            detailReportList.add(element);
        }
        return detailReportList;
    }

    private ExtensionsType generateExtensions(X509Certificate cert) throws Exception {
        ExtensionsType extensions = new ExtensionsType();
        ExtendedKeyUsage keyUsage = (ExtendedKeyUsage) cert.getExtension(ObjectID.certExt_ExtendedKeyUsage);
        if (keyUsage != null) {
            ExtensionType extension = new ExtensionType();
            extension.setExtensionOK(generateVerificationResult(MAJORCODE_PASS, "ok"));
            extension.setCritical(keyUsage.isCritical());
            ObjectIdentifierType oid = new ObjectIdentifierType();
            oid.setDescription("Key Usage");
            IdentifierType idType = new IdentifierType();
            idType.setValue(ObjectID.certExt_KeyUsage.getName());
            idType.setQualifier(QualifierType.OID_AS_URI);
            oid.setIdentifier(idType);
            extension.setExtnId(oid);
            String value = keyUsage.toString();
            Property property = new Property();
            String bae64 = Util.toBase64String(value.getBytes());
            Base64Data data = new Base64Data();
            data.setValue(bae64.getBytes());
            data.setMimeType("app/cert-extension-content");
            property.setIdentifier("Extended_Key_usage");
            List<Object> values = new ArrayList<>();
            values.add(value);
            AnyType extn = new AnyType();
            extn.getAny().addAll(values);
            extension.setExtnValue(extn);
        }
        return extensions;
    }

    private CertificateContentType generateCertificateContent(X509Certificate cert) throws Exception {
        CertificateContentType certContent = new CertificateContentType();
        certContent.setSerialNumber(cert.getSerialNumber());
        certContent.setSignatureAlgorithm(cert.getSigAlgName());
        certContent.setIssuer(cert.getIssuerDN().getName());
        certContent.setSubject(cert.getSubjectDN().getName());
        certContent.setVersion(BigInteger.valueOf((long)cert.getVersion()));
        ExtensionsType extensions = generateExtensions(cert);
        certContent.setExtensions(extensions);
        return certContent;
    }

    private VerificationResultType generateVerificationResult (String resultMajor, String message){
        VerificationResultType result = new VerificationResultType();
        result.setResultMajor(resultMajor);
        InternationalStringType international = new InternationalStringType();
        international.setLang("EN");
        international.setValue(message);
        result.setResultMessage(international);
        return result;
    }

    public VerificationReportType getReport() {
        return report;
    }

    public IndividualReportType getIndividualReport() {
        return individualReport;
    }

    public VerifyUtil.VerifierResult getCheckResult() {
        return checkResult;
    }

    public List<VerifyUtil.SignerInfoCheckResults> getInfoResult() {
        return infoResult;
    }

    public List<JAXBElement<DetailedSignatureReportType>> getDetailList() {
        return detailList;
    }
}
