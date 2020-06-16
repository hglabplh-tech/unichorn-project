package org.harry.security.util;


import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.GeneralName;
import iaik.security.provider.IAIK;
import iaik.x509.X509Certificate;
import iaik.x509.attr.AttributeCertificate;
import iaik.x509.attr.Holder;
import iaik.x509.attr.V2Form;
import iaik.x509.attr.attributes.Role;
import iaik.x509.attr.extensions.NoRevAvail;
import iaik.xml.crypto.XSecProvider;
import iaik.xml.crypto.XmldsigMore;
import iaik.xml.crypto.utils.KeySelectorImpl;
import iaik.xml.crypto.utils.URIDereferencerImpl;
import iaik.xml.crypto.xades.*;
import iaik.xml.crypto.xades.dom.DOMExtensionContext;
import iaik.xml.crypto.xades.impl.HTTPTSPTimeStampProcessor;
import iaik.xml.crypto.xades.impl.dom.XAdESSignatureFactory;
import iaik.xml.crypto.xades.timestamp.TimeStampProcessor;
import org.harry.security.util.certandkey.KeyStoreTool;
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
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
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
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.*;

import static java.util.Arrays.asList;
import static java.util.Collections.nCopies;
import static org.harry.security.CommonConst.TSP_URL;


public class SignXAdESUtil {

    private PrivateKey privateKey;

    private Certificate[] certChain;

    Tuple<PrivateKey, X509Certificate[]> secondKeys = null;

    private XAdESSignatureFactory sfac;

    private QualifyingPropertiesFactory qfac;
    private KeyInfoFactory kif;
    private XAdESSignature signature;
    private Document doc;
    private DOMSignContext context;
    private XAdESParams params = new XAdESParams();
    private String signedPropsId;

    public SignXAdESUtil(PrivateKey key, Certificate[] certChain) throws Exception {
        this.privateKey = key;
        this.certChain = certChain;
        XSecProvider xSecProvider = new XSecProvider();
        Security.addProvider(xSecProvider);

        sfac = (XAdESSignatureFactory) XAdESSignatureFactory.getInstance("DOM", xSecProvider);
        qfac = QualifyingPropertiesFactory.getInstance("DOM", xSecProvider);
        kif = KeyInfoFactory.getInstance("DOM", xSecProvider);
    }

    public void getSecondCert(InputStream fis, String pw, String alias)
            throws GeneralSecurityException, IOException {
        System.out
                .println("reading signature key and certificates ");
        KeyStore store = KeyStoreTool.loadStore(fis,pw.toCharArray(), "PKCS12");
        secondKeys = KeyStoreTool.getKeyEntry(store, alias, pw.toCharArray());

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
            ProdPlace place = params.getProductionPlace();
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
        List<CounterSignature> counterSigs = null;
        if (params.getCounterSignature() != null) {
            CounterSignature cs = params.getCounterSignature();
            counterSigs = Collections.nCopies(1, cs);
        }
        SignaturePolicyIdentifier spiden = null;
        if (params.isGenPolicy()) {
            spiden = generatePolicy();
        }
        // Create SignedProperties
        SignedSignatureProperties ssp =
                qfac.newSignedSignatureProperties(st, sc, spiden, prodPlace, theRole, null);
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
            TimeStampProcessor processor = new HTTPTSPTimeStampProcessor(params.getTSA_URL());
            context.put(TimeStampProcessor.PROPERTY, processor);
        }
    }

    private SignaturePolicyIdentifier generatePolicy() throws FileNotFoundException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        // Create the SignaturePolicyIdentifier qualifying property
       InputStream policyStream  = SignXAdESUtil.class.getResourceAsStream("/crypto/xmlsigs/SigPolicy.xml");
        Data spis = new OctetStreamData(
                new BufferedInputStream(policyStream), "/crypto/xmlsigs/SigPolicy.xml", "text/xml");

        ObjectIdentifier oi = qfac.newObjectIdentifier("http://www.iaik.at/foo/SigPolicy",
                null, "IAIK foo signature policy", null);

        List spqualifiers = new ArrayList();
        List spuris = new ArrayList();
        spuris.add(qfac.newSPURI("resources/SigPolicy.xml"));
        spqualifiers.add(qfac.newSigPolicyQualifier(spuris));
        List spusernotices = new ArrayList();
        spusernotices.add(qfac.newSPUserNotice("This is a demo signature only.", null));
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
        XMLExtendContext exContext = new DOMExtensionContext(valContext);
        SignatureTimeStamp tsp = this.qfac.newSignatureTimeStamp(sfac.newCanonicalizationMethod(params.getCanonMethod(), (C14NMethodParameterSpec) null),
                "timeStampID" + UUID.randomUUID().toString(), null);
        TimeStampProcessor processor = new HTTPTSPTimeStampProcessor(params.getTSA_URL());
        exContext.put(TimeStampProcessor.PROPERTY, processor);
        signature.appendSignatureTimeStamp(tsp, exContext);
    }

    private CounterSignature createCounterSignature(InputStream fis, String passwd, String alias) throws Exception  {
        // Create a CounterSignature
        getSecondCert(fis,passwd, alias);
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
        KeyValue kv = kif.newKeyValue(secondKeys.getSecond()[0].getPublicKey());

        // Create a KeyInfo and add the KeyValue to it
        KeyInfo cski = kif.newKeyInfo(Collections.nCopies(1, kv));

        // Create counter signature
        XMLSignature cs = sfac.newXMLSignature(csSI, cski);

        // Create the XAdES CounterSignature property
        CounterSignature counterSignature = qfac.newCounterSignature(cs,
                KeySelector.singletonKeySelector(secondKeys.getFirst()));
        return counterSignature;
    }

    public void sign(OutputStream targetXML) throws Exception {
        signature.sign(context);
        DOMValidateContext valContext = switchToDomValidateContext();
        valContext.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
        if (params.isSetSigTimeStamp()) {
            setSignatureTimeStamp(valContext);
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
        private CounterSignature counterSignature = null;
        private ProdPlace productionPlace = null;
        private boolean genPolicy = false;


        public String getTSA_URL() {
            return TSA_URL;
        }

        public void setTSA_URL(String TSA_URL) {
            this.TSA_URL = TSA_URL;
        }



        public Optional<AttributeCertificate> getSignerRole() {
            return signerRole;
        }

        public void setSignerRole(AttributeCertificate signerRole) {
            this.signerRole = Optional.of(signerRole);
        }

        public String getDigestAlg() {
            return digestAlg;
        }

        public void setDigestAlg(String digestAlg) {
            this.digestAlg = digestAlg;
        }

        public String getSignatureAlg() {
            return signatureAlg;
        }

        public void setSignatureAlg(String signatureAlg) {
            this.signatureAlg = signatureAlg;
        }


        public boolean isSetSigTimeStamp() {
            return setSigTimeStamp;
        }

        public void setSetSigTimeStamp(boolean setSigTimeStamp) {
            this.setSigTimeStamp = setSigTimeStamp;
        }

        public boolean isSetContentTimeStamp() {
            return setContentTimeStamp;
        }

        public void setSetContentTimeStamp(boolean setContentTimeStamp) {
            this.setContentTimeStamp = setContentTimeStamp;
        }

        public CounterSignature getCounterSignature() {
            return this.counterSignature;
        }

        public void setCounterSignature(CounterSignature counterSig) {
            this.counterSignature = counterSig;
        }

        public boolean isSetArchiveTimeStamp() {
            return setArchiveTimeStamp;
        }

        public void setSetArchiveTimeStamp(boolean setArchiveTimeStamp) {
            this.setArchiveTimeStamp = setArchiveTimeStamp;
        }

        public ProdPlace getProductionPlace() {
            return productionPlace;
        }

        public void setProductionPlace(ProdPlace addProductionPlace) {
            this.productionPlace = addProductionPlace;
        }

        public boolean isGenPolicy() {
            return genPolicy;
        }

        public void setGenPolicy(boolean genPolicy) {
            this.genPolicy = genPolicy;
        }

        public String getCanonMethod() {
            return canonMethod;
        }

        public void setCanonMethod(String canonMethod) {
            this.canonMethod = canonMethod;
        }

    }

    public static class ProdPlace {
        private String city;
        private String street;
        private String zipCode;
        private String region;
        private String country;

        public String getCity() {
            return city;
        }

        public ProdPlace setCity(String city) {
            this.city = city;
            return this;
        }

        public String getStreet() {
            return street;
        }

        public ProdPlace setStreet(String street) {
            this.street = street;
            return this;
        }

        public String getZipCode() {
            return zipCode;
        }

        public ProdPlace setZipCode(String zipCode) {
            this.zipCode = zipCode;
            return this;
        }

        public String getRegion() {
            return region;
        }

        public ProdPlace setRegion(String region) {
            this.region = region;
            return this;
        }

        public String getCountry() {
            return country;
        }

        public ProdPlace setCountry(String country) {
            this.country = country;
            return this;
        }
    }

}
