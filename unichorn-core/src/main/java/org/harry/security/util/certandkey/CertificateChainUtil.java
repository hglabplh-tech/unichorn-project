package org.harry.security.util.certandkey;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.Name;
import iaik.asn1.structures.RDN;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.X509ExtensionInitException;
import iaik.x509.extensions.AuthorityKeyIdentifier;
import iaik.x509.extensions.SubjectKeyIdentifier;
import org.harry.security.util.CertificateWizzard;
import org.harry.security.util.Tuple;
import org.harry.security.util.VerifyUtil;
import org.harry.security.util.trustlist.TrustListManager;
import org.pmw.tinylog.Logger;

import java.security.KeyStore;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

public class CertificateChainUtil {

    /**
     * Search the issuer of a certificate in the complete certificates list.
     * This is done by comparing the issuer dn and the subject and authority keys of the cedrtificates
     * @param actualCert the certificate for which we like to lookup the issuer
     * @return the optional holding the issuer
     */
    public static Optional<X509Certificate> findIssuer(X509Certificate actualCert, List<X509Certificate> certificates) {
        Optional<X509Certificate> opt = certificates.stream().filter(e -> {
            X509Certificate cert = e;
            if (actualCert.getIssuerDN().getName().equals(cert.getSubjectDN().getName())) {
                AuthorityKeyIdentifier authID = null;
                try {
                    authID = (AuthorityKeyIdentifier)
                            actualCert.getExtension(AuthorityKeyIdentifier.oid);
                } catch (X509ExtensionInitException x509ExtensionInitException) {
                    return false;
                }
                if (authID != null) {
                    SubjectKeyIdentifier skeyid = null;
                    try {
                        skeyid = (SubjectKeyIdentifier) cert.getExtension(SubjectKeyIdentifier.oid);
                    } catch (X509ExtensionInitException x509ExtensionInitException) {
                        return false;
                    }
                    Logger.trace("Compare Subject Key : "
                            + Arrays.toString(skeyid.get()));
                    Logger.trace("to Authentication Key: "
                            + Arrays.toString(authID.getKeyIdentifier()));
                    if (Arrays.equals(authID.getKeyIdentifier(), skeyid.get())) {
                            Logger.trace("Issuer found: " + cert.getSubjectDN().getName()
                                    + " Serial: " + cert.getSerialNumber());
                            return true;
                        }
                    }
                } else {
                    if (CertificateWizzard.isCertificateSelfSigned(actualCert)) {
                            return true;
                    }
                }
                return false;
            }
        ).findFirst();
        return opt;
    }

    public static X509Certificate[] resolveTrustedChain(X509Certificate certificate,
                                                        X509Certificate[] chainIN,
                                                        List<TrustListManager> walkers,
                                                        List<X509Certificate> certificates) {
        if (certificates == null) {
            certificates = new ArrayList<>();
            loadTrustCerts(certificates);
        }
        if (chainIN == null) {
            X509Certificate[] certArray = new X509Certificate[0];
            X509Certificate actualCert = certificate;
            int index = 0;
            while (!CertificateWizzard.isCertificateSelfSigned(actualCert)) {
                Optional<X509Certificate> certOpt = Optional.empty();
                certOpt = getX509IssuerCertificate(actualCert, certOpt, walkers, certificates);
                if (certOpt.isPresent()) {
                    System.out.println("found subject:" + certOpt.get().getSubjectDN().getName());
                    certArray = allocAndAssign(certArray, actualCert);
                    certArray = allocAndAssign(certArray, certOpt.get());
                }
                if (certOpt.isPresent()) {
                    actualCert = certOpt.get();
                } else {
                    break;
                }
                index++;
            }
            return certArray;

        } else {
            X509Certificate[] result = Util.arrangeCertificateChain(chainIN, false);
            if (chainIN[0].equals(certificate)) {
                boolean isOneTrusted = false;
                for (X509Certificate actualCert: result) {
                    Optional<X509Certificate> certOpt = Optional.empty();
                    certOpt = getX509IssuerCertificate(actualCert, certOpt, walkers, certificates);
                    if (certOpt.isPresent()) {
                        isOneTrusted = true;
                    }
                }
                if (isOneTrusted) {
                    return result;
                } else {
                    return new X509Certificate[0];
                }
            } else {
                return new X509Certificate[0];
            }
        }
    }

    /**
     * retrieve the issuers cedrtificate by searching it in the trust list
     * @param signCert the signers certificate
     * @param certOpt the certificate optional holding the issuer later on
     * @return the optional holding the found cdertificate
     */
    public static Optional<X509Certificate> getX509IssuerCertificate(X509Certificate signCert,
                                                                     Optional<X509Certificate> certOpt,
                                                                     List<TrustListManager> walkers,
                                                                     List<X509Certificate> certificates) {

        for (TrustListManager walker : walkers) {
            certOpt = walker.getAllCerts()
                    .stream().filter(e -> {
                        try {
                            RDN commonIssuer = ((Name) signCert.getIssuerDN()).element(ObjectID.commonName);
                            String issuer = commonIssuer.getRFC2253String();
                            RDN commonSubject = ((Name) e.getSubjectDN()).element(ObjectID.commonName);
                            String subject = commonSubject.getRFC2253String();
                            return issuer.equals(subject);
                        } catch (Exception ex) {
                            return false;
                        }

                    })
                    .findFirst();
            if (certOpt.isPresent()) {
                break;
            }
        }
        if (!certOpt.isPresent()) {
            certOpt = certificates.stream().filter(e -> {
                try {
                    RDN commonIssuer = ((Name) signCert.getIssuerDN()).element(ObjectID.commonName);
                    String issuer = commonIssuer.getRFC2253String();
                    RDN commonSubject = ((Name) e.getSubjectDN()).element(ObjectID.commonName);
                    String subject = commonSubject.getRFC2253String();
                    return issuer.equals(subject);
                } catch (Exception ex) {
                    return false;
                }

            }).findFirst();
        }
        return certOpt;
    }

    public static X509Certificate[] allocAndAssign(X509Certificate[] certChain, X509Certificate certToAssign) {
        X509Certificate[] temp = new X509Certificate[certChain.length + 1];
        int index = 0;
        for (; index < certChain.length; index++) {
            temp[index] = certChain[index];
        }
        temp[index] = certToAssign;
        return temp;
    }


    public static List<X509Certificate> addToCertificateList(X509Certificate[] chain, List<X509Certificate> temp) {
        for (X509Certificate certificate : chain) {
            temp.add(certificate);
        }
        return temp;
    }

    public static List<X509Certificate> loadTrustCerts(List<X509Certificate> certificates) {
        try {
            KeyStore trustStore = KeyStoreTool.loadTrustStore();
            Enumeration<String> aliases = trustStore.aliases();
            while(aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Logger.trace("load alias: " + alias);
                X509Certificate cert = KeyStoreTool.getCertificateEntry(trustStore, alias);
                X509Certificate[] chain = new X509Certificate[1];
                chain[0] = cert;
                addToCertificateList(chain, certificates);
            }
            return certificates;
        } catch (Exception ex) {
            Logger.trace("not loaded cause is: " + ex.getMessage());
            throw new IllegalStateException("not loaded keys", ex);
        }
    }
}
