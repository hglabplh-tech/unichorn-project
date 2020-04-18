package org.harry.security.util.trustlist;

import iaik.x509.X509Certificate;
import org.etsi.uri._02231.v2_.*;

import javax.xml.bind.*;
import javax.xml.namespace.QName;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.CertificateEncodingException;
import java.util.List;

public class TrustListLoader {

    private TrustStatusListType trustList;

    private List<DigitalIdentityType> listDigi;
    public void makeRoot() {
        trustList = new TrustStatusListType();
        trustList.setId("Unichorn");
        TSLSchemeInformationType scheme = new TSLSchemeInformationType();
        scheme.setSchemeTerritory("DE");
        trustList.setSchemeInformation(scheme);
        trustList.setTSLTag("private");
        TrustServiceProviderListType list = new TrustServiceProviderListType();
        TSPType type = new TSPType();
        TSPInformationType info = new TSPInformationType();
        TSPServicesListType tspList = new TSPServicesListType();
        TSPServiceType service = new TSPServiceType();
        TSPServiceInformationType tspInfo = new TSPServiceInformationType();
        DigitalIdentityListType digital = new DigitalIdentityListType();
        listDigi = digital.getDigitalId();
        tspInfo.setServiceDigitalIdentity(digital);
        service.setServiceInformation(tspInfo);
        tspList.getTSPService().add(service);
        type.setTSPServices(tspList);
        list.getTrustServiceProvider().add(type);
        trustList.setTrustServiceProviderList(list);
    }

    public void addX509Cert(X509Certificate cert) throws CertificateEncodingException {
        DigitalIdentityType identity = new DigitalIdentityType();
        identity.setX509Certificate(cert.getEncoded());
        listDigi.add(identity);
    }
    public static TrustStatusListType loadTrust(InputStream trustList) {
        JAXBContext jaxbContext;
        try
        {
            jaxbContext = JAXBContext.newInstance(TrustStatusListType.class);
            Unmarshaller umarshall  = jaxbContext.createUnmarshaller();

            JAXBElement root = (JAXBElement) umarshall.unmarshal(trustList);


            System.out.println(root.getValue());

            return (TrustStatusListType)root.getValue();
        }
        catch (JAXBException ex)
        {
            throw new IllegalStateException("trust list not loaded", ex);
        }
    }

    public void storeTrust(OutputStream out) {
        JAXBContext jaxbContext;
        try
        {
            jaxbContext = JAXBContext.newInstance(TrustStatusListType.class);
            QName qName = new QName("http://uri.etsi.org/02231/v2#", "TrustServiceStatusList");
            JAXBElement<TrustStatusListType> root = new JAXBElement<TrustStatusListType>(qName,
                    TrustStatusListType.class, trustList);

            Marshaller marshal  = jaxbContext.createMarshaller();
            marshal.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marshal.marshal(root, out);




            return;
        }
        catch (JAXBException ex)
        {
            throw new IllegalStateException("trust list not loaded", ex);
        }
    }
}
