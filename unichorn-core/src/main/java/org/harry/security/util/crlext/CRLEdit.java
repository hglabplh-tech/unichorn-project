package org.harry.security.util.crlext;

import iaik.asn1.structures.AlgorithmID;
import iaik.utils.ASN1InputStream;
import iaik.x509.RevokedCertificate;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.X509ExtensionException;
import iaik.x509.extensions.ReasonCode;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Principal;
import java.security.PrivateKey;
import java.util.Calendar;
import java.util.Date;

public class CRLEdit {

    private X509CRL crList = null;

    public CRLEdit(InputStream stream) {
        crList = readCrl(stream);
    }

    public CRLEdit(Principal issuer) {
        X509CRL crlList = new X509CRL();
        crlList.setIssuerDN(issuer);

        Calendar cal = Calendar.getInstance();
        cal.set(Calendar.WEEK_OF_MONTH,(cal.get(Calendar.WEEK_OF_MONTH) -1));
        crlList.setThisUpdate(new Date(cal.getTimeInMillis()));
        cal.add(Calendar.WEEK_OF_YEAR, 5);
        crlList.setNextUpdate(new Date(cal.getTimeInMillis()));
        crlList.setSignatureAlgorithm(AlgorithmID.sha256WithRSAEncryption);
        crList = crlList;
    }

    public void addCertificate(X509Certificate certificate, ReasonCode code) throws X509ExtensionException {
        Date date = certificate.getNotAfter();
        certificate.addExtension(code);
        crList.addCertificate(certificate, date);
    }

    public void addRevokedCertificate(X509Certificate certificate, ReasonCode code) throws X509ExtensionException {
        Calendar cal = Calendar.getInstance();
        cal.set(Calendar.WEEK_OF_MONTH,(cal.get(Calendar.WEEK_OF_MONTH) -1));
        Date actualDate = new Date(cal.getTimeInMillis());
        RevokedCertificate revoked = new RevokedCertificate(certificate, actualDate);
        revoked.addExtension(code);
        crList.addCertificate(revoked);
    }

    public void signCRL(X509Certificate signer, PrivateKey key) {
        crList.setIssuerDN(signer.getSubjectDN());
        try {
            crList.sign(key);
        } catch(Exception ex) {
            throw new IllegalStateException("cannot be signed", ex);
        }
    }

    public void storeCRL(OutputStream out) {
        try {
            crList.writeTo(out);
            out.close();
        } catch(Exception ex) {
            throw new IllegalStateException("cannot be stored as signed", ex);
        }
    }

    /**
     * Reads a X.509 crl from the given file.
     *
     * @param is
     *          the name of the crl file
     * @return the crl
     */
    private static X509CRL readCrl(InputStream is) {

        X509CRL crl = null;
        try {
            crl = new X509CRL(new ASN1InputStream(is));
        } catch (Exception ex) {
            ex.printStackTrace();
            System.exit(-1);
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        }
        return crl;
    }

}
