package org.harry.security.util.crlext;

import iaik.utils.ASN1InputStream;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.util.Date;

public class CRLEdit {

    private X509CRL crList = null;

    public CRLEdit(InputStream stream) {
        crList = readCrl(stream);
    }

    public void addCertificate(X509Certificate certificate) {
        Date date = certificate.getNotAfter();
        crList.addCertificate(certificate, date);
    }

    public void signCRL(X509Certificate signer, PrivateKey key) {
        crList.setIssuerDN(signer.getIssuerDN());
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
