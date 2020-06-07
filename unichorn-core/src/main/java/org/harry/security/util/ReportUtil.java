package org.harry.security.util;

import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.DetailedSignatureReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ObjectFactory;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;
import org.etsi.uri._02231.v2_.TrustStatusListType;
import org.pmw.tinylog.Logger;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Marshaller;
import javax.xml.namespace.QName;
import java.io.File;
import java.io.FileOutputStream;
import java.util.List;

public class ReportUtil {

    public static void generateAndWriteReport(File reportFile, VerifyUtil.VerifierResult result) {
        try {
            VerifyReporter reporter = new VerifyReporter(result);
            VerificationReportType report = reporter.generateReport();
            FileOutputStream out = new FileOutputStream(reportFile);
            JAXBContext jaxbContext = JAXBContext.newInstance(VerificationReportType.class);
            QName qName = new QName("urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:schema#", "VerificationReportType");
            JAXBElement<VerificationReportType> root = new JAXBElement<VerificationReportType>(qName,
                    VerificationReportType.class, report);

            Marshaller marshal = jaxbContext.createMarshaller();
            marshal.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marshal.marshal(root, out);
        } catch (Exception ex) {
            Logger.trace("Cannot generate verificationReport" + ex.getMessage());
            Logger.trace(ex);
            throw new IllegalStateException("Cannot generate verificationReport", ex);
        }
    }
}
