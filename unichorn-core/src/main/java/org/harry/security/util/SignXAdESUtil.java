package org.harry.security.util;


import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.GeneralName;
import iaik.asn1.structures.Name;
import iaik.security.provider.IAIKMD;
import iaik.utils.RFC2253NameParser;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.attr.AttributeCertificate;
import iaik.x509.attr.Holder;
import iaik.x509.attr.V2Form;
import iaik.x509.attr.attributes.Role;
import iaik.x509.attr.extensions.NoRevAvail;
import iaik.x509.ocsp.OCSPResponse;
import iaik.x509.ocsp.ReqCert;
import iaik.xml.crypto.XSecProvider;
import iaik.xml.crypto.XmldsigMore;
import iaik.xml.crypto.utils.KeySelectorImpl;
import iaik.xml.crypto.utils.URIDereferencerImpl;
import iaik.xml.crypto.xades.*;
import iaik.xml.crypto.xades.dom.DOMExtensionContext;
import iaik.xml.crypto.xades.impl.dom.XAdESSignatureFactory;
import iaik.xml.crypto.xades.timestamp.TimeStampProcessor;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.ocsp.HttpOCSPClient;
import org.harry.security.util.trustlist.TrustListManager;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.crypto.Data;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URI;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.*;

import static java.util.Arrays.asList;
import static java.util.Collections.nCopies;
import static org.harry.security.CommonConst.*;


public class SignXAdESUtil {

    private PrivateKey privateKey;

    private Certificate[] certChain;

    private XAdESSignatureFactory sfac;

    private QualifyingPropertiesFactory qfac;
    private KeyInfoFactory kif;
    private XAdESSignature signature;
    private Document doc;
    private DOMSignContext context;
    private XAdESParams params = new XAdESParams();
    private String signedPropsId;
    private XMLExtendContext exContext;
    private List<TrustListManager> walker;

    public SignXAdESUtil(PrivateKey key, Certificate[] certChain, boolean pkcs11) throws Exception {
        this.privateKey = key;
        this.certChain = certChain;
        walker = ConfigReader.loadAllTrusts();
        Provider xSecProvider = null;
        if ( !pkcs11) {
            IAIKMD.addAsProvider();
            xSecProvider = new XSecProvider();
            Security.insertProviderAt(xSecProvider, 3);
            //move other XMLDsig provider to the end
            Provider otherXMLDsigProvider = Security.getProvider("XMLDSig");
            if (otherXMLDsigProvider != null) {
                Security.removeProvider(otherXMLDsigProvider.getName());
                Security.addProvider(otherXMLDsigProvider);
            }
        } else {

        }

        sfac = (XAdESSignatureFactory) XAdESSignatureFactory.getInstance("DOM", xSecProvider);
        qfac = QualifyingPropertiesFactory.getInstance("DOM", xSecProvider);
        kif = KeyInfoFactory.getInstance("DOM", xSecProvider);
    }

    /**
     * method for prepare signing with all requested parameteers TODO pack the parameters into a sign parameter class
     * @param sourceXML the inpput xml stream
     * @param params the parameter object for building a signature     *
     * @throws Exception error case
     */
    public void prepareSigning(InputStream sourceXML, XAdESParams params) throws  Exception {
        String sigBaseId = UUID.randomUUID().toString();
        signedPropsId = "SignedProperties-" + sigBaseId;
        String signatureId = "Signature-" + sigBaseId;
        loadXMLDoc(sourceXML);

        X509Certificate [] signerChain = new X509Certificate[certChain.length];
        int index = 0;
        for (Certificate cert: certChain) {
            signerChain[index] = new X509Certificate(cert.getEncoded());
            index++;
        }
        this.params = params;
        // reference to the signed properties
        Reference spRef = sfac.newReference(
                "#" + signedPropsId, sfac.newDigestMethod(params.getDigestAlg(), null),
                asList(sfac.newTransform(params.getCanonMethod(), (TransformParameterSpec) null)),
                SignedProperties.REFERENCE_TYPE, "SignedProperties-Reference-" + sigBaseId);
        // reference to the data itself (enveloped)
        Reference ref = sfac.newReference(
                "",
                sfac.newDigestMethod(params.getDigestAlg(), null),
                Collections.singletonList
                        (sfac.newTransform
                                (Transform.ENVELOPED, (TransformParameterSpec) null)),
                null, null);

        CanonicalizationMethod canonicalizationMethod =
                sfac.newCanonicalizationMethod(
                        params.getCanonMethod(),
                        (C14NMethodParameterSpec) null);
        SignatureMethod signatureMethod = sfac.newSignatureMethod(
                params.getSignatureAlg(), null);
        SignedInfo si = sfac.newSignedInfo(
                canonicalizationMethod, signatureMethod,
                asList( ref, spRef), "SignedInfo-" + sigBaseId);

        CertIDV2 certID = qfac.newCertIDV2(null, signerChain[0], sfac.newDigestMethod(params.getDigestAlg(), null),true);
        SigningCertificateV2 sc = qfac.newSigningCertificateV2(Collections.singletonList(certID));
        SigningTime st = null;
        st = qfac.newSigningTime();
        SignatureProductionPlaceV2 prodPlace = null;
        if (params.getProductionPlace() != null) {
            VerificationResults.ProdPlace place = params.getProductionPlace();
            prodPlace = qfac.newSignatureProductionPlaceV2(place.getCity(),
                    place.getStreet(),
                    place.getRegion(),
                    place.getZipCode(),
                    place.getCountry());
        }


        SignerRoleV2 theRole = null;
        if (params.getSignerRole().isPresent()) {
            theRole = getSignerRoleV2(params);
        }
        List<CounterSignature> counterSigs = new ArrayList<>();
        if (params.getCounterSigKeys().isPresent()) {
            Tuple<PrivateKey, X509Certificate[]> keys = params.getCounterSigKeys().get();
            CounterSignature cs = createCounterSignature(keys);
            counterSigs = Collections.nCopies(1, cs);
        }
        SignaturePolicyIdentifier spiden = null;
        if (params.isGenPolicy()) {
            spiden = generatePolicy();
        }
        SignedSignatureProperties ssp =
                qfac.newSignedSignatureProperties(st, sc, spiden, prodPlace, theRole, null);
        // Create SignedProperties
        SignedDataObjectProperties sdp = null;
        if (params.isSetContentTimeStamp()) {
            sdp = setAllDataObjTSP(params.getCanonMethod());
        }
        SignedProperties sp = qfac.newSignedProperties(ssp, sdp, signedPropsId);


        // Create QualifyingProperties
        UnsignedProperties up = qfac.newUnsignedProperties(qfac.newUnsignedSignatureProperties(counterSigs, null)
                , null, null);
        QualifyingProperties qp = qfac.newQualifyingProperties(sp, up, "#" + signatureId, null);
        XMLObject qpObj = sfac.newXMLObject(nCopies(1, qp), null, null, null);


        X509Data x509data = kif.newX509Data(
                Arrays.asList(signerChain));
        KeyInfo ki = kif.newKeyInfo(Collections.nCopies(1, x509data));

        signature = (XAdESSignature) sfac.newXMLSignature(si, ki, Arrays.asList(qpObj), signatureId, "SignatureValue-" + sigBaseId);
        context = new DOMSignContext(privateKey, doc.getDocumentElement());
        context.setURIDereferencer(new URIDereferencerImpl());
        context.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
        context.putNamespacePrefix(XMLSignature.XMLNS, "ds");
        context.putNamespacePrefix(XAdESSignature.XMLNS_1_4_1, "xades");
        if (params.isSetContentTimeStamp()) {
            TimeStampProcessor processor = new SimpleTimeStampProcessor(params.getTSA_URL());
            context.put(TimeStampProcessor.PROPERTY, processor);
        }
    }

    private SignaturePolicyIdentifier generatePolicy() throws FileNotFoundException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        // Create the SignaturePolicyIdentifier qualifying property
       InputStream policyStream  = SignXAdESUtil.class.getResourceAsStream("/signatures/UnichornPolicy.xml");
        Data spis = new OctetStreamData(
                new BufferedInputStream(policyStream), "/signatures/UnichornPolicy.xml", "text/xml");

        ObjectIdentifier oi = qfac.newObjectIdentifier("http://www.unichorn.de/policy/all",
                null, "Harrys Policy", null);

        List spqualifiers = new ArrayList();
        List spuris = new ArrayList();
        spuris.add(qfac.newSPURI("/resources/signatures/UnichornPolicy.xml"));
        spqualifiers.add(qfac.newSigPolicyQualifier(spuris));
        List spusernotices = new ArrayList();
        spusernotices.add(qfac.newSPUserNotice("This is a default signature only.", null));
        spqualifiers.add(qfac.newSigPolicyQualifier(spusernotices));

        SignaturePolicyId spid = qfac.newSignaturePolicyId(oi, null,
                sfac.newDigestMethod(params.getDigestAlg(), null), spis, spqualifiers);

        return qfac.newSignaturePolicyIdentifier(spid);
    }

    private SignerRoleV2 getSignerRoleV2(XAdESParams params) throws CertificateEncodingException {
        SignerRoleV2 theRole;
        X509AttributeCertificate cert = qfac.newX509AttributeCertificate(params.getSignerRole().get().getEncoded(), null, null);
        CertifiedRoleV2 role = qfac.newCertifiedRoleV2(cert);
        theRole = qfac.newSignerRoleV2(null, Arrays.asList(role), null);
        return theRole;
    }


    private void loadXMLDoc(InputStream sourceXML) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setIgnoringElementContentWhitespace(true);
        dbf.setExpandEntityReferences(false);
        DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
        doc = documentBuilder.parse(sourceXML);
    }

    private SignedDataObjectProperties setAllDataObjTSP(String canonMethod) throws Exception {
        // add an AllDataObjectsTimeStamp
        AllDataObjectsTimeStamp allDataObjectsTimeStamp = qfac.newAllDataObjectsTimeStamp(
                sfac.newCanonicalizationMethod(canonMethod,
                        (C14NMethodParameterSpec) null), "AllDataObjectsTimeStamp-1", null);
        List<AllDataObjectsTimeStamp> dataObjectTimeStamps = new ArrayList<>();
        dataObjectTimeStamps.add(allDataObjectsTimeStamp);
        SignedDataObjectProperties sdp = qfac.newSignedDataObjectProperties(null, null, dataObjectTimeStamps,
                null, null);
        return sdp;
    }

    private void setSignatureTimeStamp(DOMValidateContext valContext) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MalformedURLException, MarshalException, XMLSignatureException {
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        exContext = new DOMExtensionContext(valContext);
        SignatureTimeStamp tsp = this.qfac.newSignatureTimeStamp(sfac.newCanonicalizationMethod(params.getCanonMethod(), (C14NMethodParameterSpec) null),
                "timeStampID" + UUID.randomUUID().toString(), null);
        TimeStampProcessor processor = new SimpleTimeStampProcessor(params.getTSA_URL());
        exContext.put(TimeStampProcessor.PROPERTY, processor);
        signature.appendSignatureTimeStamp(tsp, exContext);
    }

    public CounterSignature createCounterSignature(Tuple<PrivateKey, X509Certificate[]> keys) throws Exception  {
        // Create a Reference to the orignal signature
        Reference csRef = sfac.newReference("#" + signedPropsId,
                sfac.newDigestMethod(params.getDigestAlg(), null), null,
                CounterSignature.REFERENCE_TYPE, null);

        // Create corresponding SignedInfo
        SignedInfo csSI = sfac.newSignedInfo(sfac.newCanonicalizationMethod(
                params.getCanonMethod(), (C14NMethodParameterSpec) null), sfac
                .newSignatureMethod(params.getSignatureAlg(), null), Collections
                .nCopies(1, csRef));


        // Create a KeyValue containing the RSA PublicKey that was generated
        KeyInfoFactory kif = sfac.getKeyInfoFactory();
        X509Data x509data = kif.newX509Data(
                Arrays.asList(keys.getSecond()));
        KeyInfo cski = kif.newKeyInfo(Collections.nCopies(1, x509data));
        // Create counter signature
        CertIDV2 certID = qfac.newCertIDV2(null, keys.getSecond()[0], sfac.newDigestMethod(params.getDigestAlg(), null),true);
        SigningCertificateV2 sc = qfac.newSigningCertificateV2(Collections.singletonList(certID));
        SignedSignatureProperties ssp =
                qfac.newSignedSignatureProperties(null, sc, null, null, null, null);
        SignedProperties sp = qfac.newSignedProperties(ssp, null, UUID.randomUUID().toString());
        QualifyingProperties qp = qfac.newQualifyingProperties(sp, null, "#" + UUID.randomUUID().toString(), null);
        XMLObject qpObj = sfac.newXMLObject(nCopies(1, qp), null, null, null);
        XMLSignature cs = sfac.newXMLSignature(csSI, cski, Arrays.asList(qpObj),
                UUID.randomUUID().toString(), "SignatureValue-" + UUID.randomUUID().toString());

        // Create the XAdES CounterSignature property
        CounterSignature counterSignature = qfac.newCounterSignature(cs,
                KeySelector.singletonKeySelector(keys.getFirst()));
        return counterSignature;
    }

    public void sign(OutputStream targetXML) throws Exception {
        signature.sign(context);
        DOMValidateContext valContext = switchToDomValidateContext();
        valContext.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
        if (params.isSetSigTimeStamp()) {
            setSignatureTimeStamp(valContext);
        }
        if (params.isAppendOCSPValues()) {
            appendOCSPResults();
        }
        processTransformWrite(targetXML);
        return;
    }

    private DOMValidateContext switchToDomValidateContext() throws Exception {
        ByteArrayOutputStream signedOut = new ByteArrayOutputStream();
        processTransformWrite(signedOut);
        ByteArrayInputStream xmlIN = new ByteArrayInputStream(signedOut.toByteArray());
        loadXMLDoc(xmlIN);
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        DOMValidateContext valContext = new DOMValidateContext(new KeySelectorImpl(),
                nl.item(0));
        // unmarshal the XMLSignature
        signature = (XAdESSignature)sfac.unmarshalXMLSignature(valContext);
        boolean coreValidity = signature.validate(valContext);
        return valContext;
    }

    private void appendOCSPResults() throws Exception {
        // Get SigningCertificate and RevocationInformation
        // And create the CompleteCertificateRefs and CompleteRevocationRefs properties
        CertIDV2 sigCert = null;
        QualifyingProperties qp = ((XAdESSignature) signature).getQualifyingProperties();
        SignedProperties sp = qp.getSignedProperties();
        if (sp != null) {
            SignedSignatureProperties ssp = sp.getSignedSignatureProperties();
            if (ssp != null) {
                SigningCertificateV2 sigCerts = ssp.getSigningCertificateV2();
                if (sigCerts != null) {
                    List certs = sigCerts.getCertIDs();
                    if (!certs.isEmpty()) {
                        sigCert = (CertIDV2) certs.get(0);
                    }
                }
            }
        }

        IssuerSerialV2 sigCertIssSer = sigCert.getIssuerSerialV2();
        String issuerName = sigCertIssSer.getIssuerName();
        RFC2253NameParser parser = new RFC2253NameParser(issuerName);
        Name name = parser.parse();
        String cn = name.getRDN(ObjectID.commonName);

        List certRefs = new ArrayList();
        List ocspRefs = new ArrayList();

        SigningBean bean = new SigningBean().setCheckPathOcsp(true);
        AlgorithmPathChecker checker = new AlgorithmPathChecker(walker, bean);
        VerificationResults.SignerInfoCheckResults results = new VerificationResults.SignerInfoCheckResults();
        X509Certificate[] realChain =
                checker.detectChain(Util.convertCertificate(this.certChain[0]),
                        null, results);
         for(int index = 0;index < realChain.length; index++) {
            if (( index + 1) < realChain.length) {
                X509Certificate cert = realChain[index];
                X509Certificate [] checkChain= new X509Certificate[2];
                checkChain[0] = cert;
                checkChain[1] = realChain[index + 1];
                BigInteger serial = cert.getSerialNumber();

                CertIDV2 certId = qfac.newCertIDV2("https://localhost/" + serial, cert,
                        sfac.newDigestMethod(params.getDigestAlg(), null), false);

                certRefs.add(certId);

                OCSPResponse response = HttpOCSPClient.sendOCSPRequest(OCSP_URL,
                        null, null, checkChain,
                        ReqCert.certID, false, true);
                String ocspFile = APP_DIR_WORKING + File.separator + cn + ".ocs";
                File ocspOutFile = new File(ocspFile);
                URI uri = ocspOutFile.toURI();
                OutputStream ocspOut = new FileOutputStream(ocspOutFile);
                response.writeTo(ocspOut);
                ocspOut.flush();
                ocspOut.close();
                ocspRefs.add(qfac.newOCSPRef(response.getEncoded(),
                        sfac.newDigestMethod(DigestMethod.SHA1, null), uri.toString()));

            }
        }

        CompleteCertificateRefsV2 compCertRefs = qfac.newCompleteCertificateRefsV2(certRefs,
                "CompleteCertificateRefs");

        CompleteRevocationRefs compRevRefs;
        compRevRefs = qfac.newCompleteRevocationRefs(null, ocspRefs, null,
                    "CompleteRevocationRefs");



        //register unmarshalled ID attributes with the new Context
        //    for (Iterator iter = valContext.iterator(); iter.hasNext();) {
        //      Map.Entry idElementEntry = (Map.Entry) iter.next();
        //      Element e = (Element) idElementEntry.getValue();
        //      extensionContext.setIdAttributeNS(e,null,"Id");
        //    }

        // Append validation references
        ((XAdESSignature) signature).appendValidationRefsV2(compCertRefs, compRevRefs, null,
                null, exContext);
    }

    private void processTransformWrite(OutputStream outputStream) throws TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer t = tf.newTransformer();
        t.transform(new DOMSource(doc), new StreamResult(outputStream));
    }

    public void createAttributeCert(OutputStream certOut) throws Exception  {
        AttributeCertificate attributeCertificate = new AttributeCertificate();
        // issuer
        V2Form v2Form = new V2Form((iaik.asn1.structures.Name) new X509Certificate(this.certChain[0].getEncoded()).getSubjectDN());
        attributeCertificate.setIssuer(v2Form);
        // holder (from base certificate)

        Holder holder = new Holder();
        holder.setBaseCertificateID(new X509Certificate(this.certChain[0].getEncoded()));
        attributeCertificate.setHolder(holder);
        // serial number
        attributeCertificate.setSerialNumber(BigInteger.valueOf(1563556764));
        // validity
        GregorianCalendar c = new GregorianCalendar();
        Date notBeforeTime = c.getTime();
        c.add(Calendar.YEAR, 3);
        Date notAfterTime = c.getTime();
        attributeCertificate.setNotBeforeTime(notBeforeTime);
        attributeCertificate.setNotAfterTime(notAfterTime);
        // add any attributes (e.g. Role):
        GeneralName roleName = new GeneralName(GeneralName.uniformResourceIdentifier, "urn:productManager");
        Role role = new Role(roleName);
        attributeCertificate.addAttribute(new Attribute(role));

        // add any extensions (e.g. No Revocation Info Available):
        NoRevAvail noRevAvail = new NoRevAvail();
        attributeCertificate.addExtension(noRevAvail);
        // sign attribute certificate
        attributeCertificate.sign(AlgorithmID.sha512WithRSAEncryption, privateKey);
        // DER encode the certificate
        attributeCertificate.writeTo(certOut);
    }

    public XAdESParams newParams() {
        return new XAdESParams();
    }

    public class XAdESParams {
        private boolean setSigTimeStamp = false;
        private boolean setContentTimeStamp = false;
        private boolean setArchiveTimeStamp = false;
        private Optional<AttributeCertificate> signerRole = Optional.empty();
        private String canonMethod = CanonicalizationMethod.EXCLUSIVE;
        private String signatureAlg = XmldsigMore.SIGNATURE_RSA_SHA256;
        private String digestAlg = DigestMethod.SHA256;
        private String TSA_URL = TSP_URL;
        private Optional<Tuple<PrivateKey, X509Certificate[]>> counterSigKeys = Optional.empty();
        private VerificationResults.ProdPlace productionPlace = null;
        private boolean genPolicy = false;
        private boolean appendOCSPValues = false;

        public boolean isSetSigTimeStamp() {
            return setSigTimeStamp;
        }

        public XAdESParams setSetSigTimeStamp(boolean setSigTimeStamp) {
            this.setSigTimeStamp = setSigTimeStamp;
            return this;
        }

        public boolean isSetContentTimeStamp() {
            return setContentTimeStamp;
        }

        public XAdESParams setSetContentTimeStamp(boolean setContentTimeStamp) {
            this.setContentTimeStamp = setContentTimeStamp;
            return this;
        }

        public boolean isSetArchiveTimeStamp() {
            return setArchiveTimeStamp;
        }

        public XAdESParams setSetArchiveTimeStamp(boolean setArchiveTimeStamp) {
            this.setArchiveTimeStamp = setArchiveTimeStamp;
            return this;
        }

        public Optional<AttributeCertificate> getSignerRole() {
            return signerRole;
        }

        public XAdESParams setSignerRole(Optional<AttributeCertificate> signerRole) {
            this.signerRole = signerRole;
            return this;
        }

        public String getCanonMethod() {
            return canonMethod;
        }

        public XAdESParams setCanonMethod(String canonMethod) {
            this.canonMethod = canonMethod;
            return this;
        }

        public String getSignatureAlg() {
            return signatureAlg;
        }

        public XAdESParams setSignatureAlg(String signatureAlg) {
            this.signatureAlg = signatureAlg;
            return this;
        }

        public String getDigestAlg() {
            return digestAlg;
        }

        public XAdESParams setDigestAlg(String digestAlg) {
            this.digestAlg = digestAlg;
            return this;
        }

        public String getTSA_URL() {
            return TSA_URL;
        }

        public XAdESParams setTSA_URL(String TSA_URL) {
            this.TSA_URL = TSA_URL;
            return this;
        }

        public Optional<Tuple<PrivateKey, X509Certificate[]>> getCounterSigKeys() {
            return counterSigKeys;
        }

        public XAdESParams setCounterSigKeys(Tuple<PrivateKey, X509Certificate[]> input) {
            this.counterSigKeys = Optional.of(input);
            return this;
        }

        public VerificationResults.ProdPlace getProductionPlace() {
            return productionPlace;
        }

        public XAdESParams setProductionPlace(VerificationResults.ProdPlace productionPlace) {
            this.productionPlace = productionPlace;
            return this;
        }

        public boolean isGenPolicy() {
            return genPolicy;
        }

        public XAdESParams setGenPolicy(boolean genPolicy) {
            this.genPolicy = genPolicy;
            return this;
        }

        public boolean isAppendOCSPValues() {
            return appendOCSPValues;
        }

        public XAdESParams setAppendOCSPValues(boolean appendOCSPValues) {
            this.appendOCSPValues = appendOCSPValues;
            return this;
        }
    }

}
