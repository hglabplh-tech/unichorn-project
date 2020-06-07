package org.harry.security.util.trustlist;



import org.etsi.uri._02231.v2_.*;
import org.pmw.tinylog.Logger;

import javax.xml.bind.*;
import javax.xml.namespace.QName;
import java.io.*;
import java.util.List;

public class TrustListLoader {

    private TrustStatusListType trustList;

    private final boolean calledFromService;

    public TrustListLoader(boolean calledFromService) {
        this.calledFromService = calledFromService;
    }

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
        InternationalNamesType intNames = new InternationalNamesType();
        intNames.getName().add("Trust List Unichorn");
        info.setTSPName(intNames);
        type.setTSPInformation(info);
        type.getTSPInformation().setTSPName(intNames);
        TSPServicesListType tspList = new TSPServicesListType();
        TSPServiceType service = new TSPServiceType();
        TSPServiceInformationType tspInfo = new TSPServiceInformationType();
        intNames = new InternationalNamesType();
        intNames.getName().add("Trust List Service Unichorn(private)");
        tspInfo.setServiceName(intNames);

        DigitalIdentityListType digital = new DigitalIdentityListType();
        listDigi = digital.getDigitalId();
        tspInfo.setServiceDigitalIdentity(digital);
        service.setServiceInformation(tspInfo);
        tspList.getTSPService().add(service);
        type.setTSPServices(tspList);
        list.getTrustServiceProvider().add(type);
        trustList.setTrustServiceProviderList(list);
    }

    /**
     * Get the class to manage the trust-list
     * @param trustListFile the file from which we may load the list
     * @return the manager
     * @throws IOException error case
     */
    public TrustListManager getManager(File trustListFile) throws Exception {
        Logger.trace("Get manager....");
        if(trustListFile != null && trustListFile.exists()) {
            InputStream stream = new FileInputStream(trustListFile);
            Logger.trace("Load trust....");
            TrustStatusListType trust = loadTrust(stream);
            Logger.trace("Trust loaded....");
            TrustListManager mgr = new TrustListManager(trust, this.calledFromService);
            trustList = trust;
            stream.close();
            Logger.trace("Get manager ok....");
            return mgr;
        } else {
            makeRoot();
            TrustListManager mgr = new TrustListManager(trustList, false);
            return mgr;
        }

    }

    public static TrustStatusListType loadTrust(InputStream trustList) throws Exception {
        JAXBContext jaxbContext;


        try {
            Logger.trace("About to unmarshall.....");
            jaxbContext = JAXBContext.newInstance(TrustStatusListType.class);
            Unmarshaller umarshall  = jaxbContext.createUnmarshaller();
            Logger.trace("About to unmarshall unmarshaller created.....");
            JAXBElement root = (JAXBElement) umarshall.unmarshal(trustList);
            Logger.trace("About to unmarshall ok.....");


            System.out.println(root.getValue());

            return (TrustStatusListType)root.getValue();
        }
        catch (JAXBException ex) {
            Logger.trace("trust list not loaded error ->: " + ex.getMessage());
            Logger.trace(ex);
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
