package org.harry.security.util;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.util.Calendar;
import java.util.Date;

public class UnicDate  {

    private final Calendar dateInternal;

    public UnicDate() {
        dateInternal = Calendar.getInstance();
    }

    public UnicDate(Calendar cal) {
        dateInternal = cal;
    }

    public UnicDate(Date date) {
        dateInternal = Calendar.getInstance();
        dateInternal.setTimeInMillis(date.getTime());
    }

    public UnicDate(XMLGregorianCalendar xmlCal) {
        dateInternal = xmlCal.toGregorianCalendar();
    }

    public XMLGregorianCalendar asXMLDate() throws DatatypeConfigurationException {
        XMLGregorianCalendar xmlCal = DatatypeFactory.newInstance().newXMLGregorianCalendar();
        xmlCal.setTime(dateInternal.get(Calendar.HOUR),
                dateInternal.get(Calendar.MINUTE),
                dateInternal.get(Calendar.SECOND),
                dateInternal.get(Calendar.MILLISECOND));
        xmlCal.setYear(dateInternal.get(Calendar.YEAR));
        xmlCal.setMonth(dateInternal.get(Calendar.MONTH));
        xmlCal.setDay(dateInternal.get(Calendar.DAY_OF_MONTH));
        return xmlCal;
    }

    public Date asDate() {
        Date date = new Date();
        date.setTime(dateInternal.getTimeInMillis());
        return date;
    }


}
