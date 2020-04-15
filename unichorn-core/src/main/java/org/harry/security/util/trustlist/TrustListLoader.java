package org.harry.security.util.trustlist;

import org.etsi.uri._02231.v2_.TrustStatusListType;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import java.io.InputStream;

public class TrustListLoader {


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
}
