package org.harry.security.util.trustlist;

import iaik.x509.X509Certificate;
import org.etsi.uri._02231.v2_.*;
import org.pmw.tinylog.Configurator;
import org.pmw.tinylog.Level;
import org.pmw.tinylog.Logger;
import org.pmw.tinylog.writers.ConsoleWriter;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Vector;

public class TrustListManager {

    private final TrustStatusListType trustList;

    private List<TSPType> tspList;

    private List<TSPServiceType> flattenTspServiceList = new ArrayList<>();

    private List<TSPServiceInformationType> flattenTspServiceInfoList = new ArrayList<>();

    private List<X509Certificate> allCerts = new ArrayList<>();

    private List<String> allSubjNames = new ArrayList<>();
    
    private List<DigitalIdentityType> listDigi = new ArrayList();

    public TrustListManager(TrustStatusListType trustList, boolean calledFromService) {
        this.trustList = trustList;
        if (!calledFromService) {
            Configurator.defaultConfig().level(Level.TRACE).writer(new ConsoleWriter()).activate();
        }
        preLoad();
    }

    public void preLoad() {
        tspList = trustList.getTrustServiceProviderList().
                getTrustServiceProvider();
        Logger.trace("About to read trust service provider  ....");
        for (TSPType type : tspList) {
            TSPServicesListType serviceList = type.getTSPServices();
            if (serviceList !=null ) {
                List<TSPServiceType> list = serviceList.getTSPService();
                if (list != null) {
                    flattenTspServiceList.addAll(list);
                }
            }
            Logger.trace("Read trust service provider ok ....");


        }
        Logger.trace("Read service list....");
        for(TSPServiceType serviceType: flattenTspServiceList) {
            flattenTspServiceInfoList.add(serviceType.getServiceInformation());
        }
        Logger.trace("Read service list ok ....");
        for(TSPServiceInformationType infoType: flattenTspServiceInfoList) {
            List<DigitalIdentityType> digitIdList = getServiceDigitalId(infoType);
            for (DigitalIdentityType id:digitIdList) {
                Logger.trace(id.getX509SubjectName());
                byte [] buffer = id.getX509Certificate();
                try {
                    if (buffer != null && buffer.length > 0) {
                        Logger.trace("get certificate");
                        X509Certificate cert = new X509Certificate(buffer);
                        Logger.trace(cert.getSubjectDN().getName());
                        allCerts.add(cert);
                    }
                    allSubjNames.add(id.getX509SubjectName());
                } catch (Throwable ex) {
                    Logger.trace("Error occurred creating certificate objex X509: -> " + ex.getMessage() +
                            "\n exception class is: -> " + ex.getClass().getCanonicalName());
                    Logger.trace(ex);
                }

            }
        }
    }

    public List<String> getAllSubjNames() {
        return allSubjNames;
    }

    public List<DigitalIdentityType> getServiceDigitalId(TSPServiceInformationType infoType) {

        for(String name : infoType.getServiceName().getName()) {
            Logger.trace("Service Name is searchiung digital id: " + name);
        }
        return infoType.getServiceDigitalIdentity().getDigitalId();
    }
    
    public void addX509Cert(Vector<String> path, X509Certificate cert) throws CertificateEncodingException {
        Optional<TSPType> item = trustList.getTrustServiceProviderList().getTrustServiceProvider().stream()
                .filter(element -> element.getTSPInformation().
                        getTSPName().getName().get(0).equals(path.get(0))).findFirst();


        if (item.isPresent()) {
            Optional<TSPServiceType> service = item.get().getTSPServices().getTSPService().stream().filter(e ->
                    e.getServiceInformation()
                        .getServiceName()
                        .getName().get(0).equals(path.get(1))).findFirst();

            if (service.isPresent()) {

                List<DigitalIdentityType> digiIDList = service.get().getServiceInformation().getServiceDigitalIdentity().getDigitalId();
                DigitalIdentityType identity = new DigitalIdentityType();
                identity.setX509Certificate(cert.getEncoded());
                digiIDList.add(identity);
            }

        }

    }


    public List<Vector<String>> collectPaths() {
        List<Vector<String>> result = new ArrayList<>();
        List<TSPType> tspTypeList = trustList.getTrustServiceProviderList().getTrustServiceProvider();
        for (TSPType type: tspTypeList) {
            List<String> name = type.getTSPInformation().getTSPName().getName();
            for(TSPServiceType service: type.getTSPServices().getTSPService()) {
                List<String> sname = service.getServiceInformation().getServiceName().getName();
                for (String nameString: name) {
                    for (String serviceString: sname) {
                        Vector<String> path = new Vector<>();
                        path.add(nameString);
                        path.add(serviceString);
                        result.add(path);
                    }
                }
            }

        }
        return result;
    }

    public void addX509Cert(X509Certificate cert) throws CertificateEncodingException {
        DigitalIdentityType identity = new DigitalIdentityType();
        identity.setX509Certificate(cert.getEncoded());
        listDigi.add(identity);
    }

    public TrustStatusListType getTrustList() {
        return trustList;
    }

    public List<TSPType> getTspList() {
        return tspList;
    }

    public List<TSPServiceType> getFlattenTspServiceList() {
        return flattenTspServiceList;
    }

    public List<TSPServiceInformationType> getFlattenTspServiceInfoList() {
        return flattenTspServiceInfoList;
    }

    public List<X509Certificate> getAllCerts() {
        return allCerts;
    }
}
