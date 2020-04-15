package org.harry.security.util.trustlist;

import iaik.x509.X509Certificate;
import org.etsi.uri._02231.v2_.*;

import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

public class TrustListWalkerAndGetter {

    private final TrustStatusListType trustList;

    private List<TSPType> tspList;

    private List<TSPServiceType> flattenTspServiceList = new ArrayList<>();

    private List<TSPServiceInformationType> flattenTspServiceInfoList = new ArrayList<>();

    private List<X509Certificate> allCerts = new ArrayList<>();

    public TrustListWalkerAndGetter(TrustStatusListType trustList) {
        this.trustList = trustList;
        preLoad();
    }

    public void preLoad() {
        tspList = trustList.getTrustServiceProviderList().
                getTrustServiceProvider();
        for (TSPType type : tspList) {
            TSPServicesListType serviceList = type.getTSPServices();
            if (serviceList !=null ) {
                List<TSPServiceType> list = serviceList.getTSPService();
                if (list != null) {
                    flattenTspServiceList.addAll(list);
                }
            }


        }
        for(TSPServiceType serviceType: flattenTspServiceList) {
            flattenTspServiceInfoList.add(serviceType.getServiceInformation());
        }
        for(TSPServiceInformationType infoType: flattenTspServiceInfoList) {
            List<DigitalIdentityType> digitIdList = getServiceDigitalId(infoType);
            for (DigitalIdentityType id:digitIdList) {
                byte [] buffer = id.getX509Certificate();
                try {
                    if (buffer != null && buffer.length > 0) {
                        X509Certificate cert = new X509Certificate(buffer);
                        allCerts.add(cert);
                    }
                } catch (CertificateException e) {
                    e.printStackTrace();
                }

            }
        }
    }

    public List<DigitalIdentityType> getServiceDigitalId(TSPServiceInformationType infoType) {
        return infoType.getServiceDigitalIdentity().getDigitalId();
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
