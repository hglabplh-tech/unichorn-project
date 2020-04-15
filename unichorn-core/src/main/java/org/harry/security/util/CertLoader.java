package org.harry.security.util;

import iaik.asn1.ObjectID;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.ExtendedKeyUsage;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.Principal;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * This class loads certificates from Windows key-store
 * @author Harald Glab-Plhak
 */
public class CertLoader {

    /**
     * This method is to retrieve certificates which are trusted from Windows
     * KeyStore
     * @return a map out of the alias and the found certificate
     */
    public static  Map<String, X509Certificate> loadCertificatesFromWIN() {

        // logic
        try {
            System.out.println("MY KeyStore Windows");
            KeyStore keyStore = KeyStore.getInstance("Windows-MY");
            keyStore.load(null, null);
            Enumeration<String> aliasEnum = keyStore.aliases();

            String userDir = System.getProperty("user.home") + "\\myCardCerts";
            System.out.println("User Dir is: " + userDir);
            File dir = new File(userDir);
            if(!dir.exists()) {
                dir.mkdirs();
            }


            Map<String,X509Certificate> certMap = new HashMap<>();

            while (aliasEnum.hasMoreElements()) {
                String alias = aliasEnum.nextElement();
                System.out.println("alias is: " + alias);
                X509Certificate cert = new X509Certificate(keyStore.getCertificate(alias).getEncoded());
                certMap.put(alias, cert);
            }
            for (Map.Entry<String, X509Certificate> entry: certMap.entrySet()) {
                X509Certificate iaikCert = new iaik.x509.X509Certificate(entry.getValue().getEncoded());
                certMap.put(entry.getKey(), iaikCert);

                boolean selected = checkCertificate(iaikCert);
                if (selected) {
                    System.out.println("Write certificate with alias: " + entry.getKey() + " to disk");
                    File certOut = new File(userDir, entry.getKey() + ".cer");
                    FileOutputStream outStream = new FileOutputStream(certOut);
                    iaikCert.writeTo(outStream);
                    X509Certificate [] certs = new X509Certificate[1];
                    certs[0] = iaikCert;

                }
            }

            System.out.println("Root KeyStore Windows");
            keyStore = KeyStore.getInstance("Windows-ROOT");
            keyStore.load(null, null);
            aliasEnum = keyStore.aliases();

            while (aliasEnum.hasMoreElements()) {
                String alias = aliasEnum.nextElement();
                System.out.println("alias is: " + alias);
                Certificate cert = keyStore.getCertificate(alias);
                X509Certificate iaikCert = new iaik.x509.X509Certificate(cert.getEncoded());
                certMap.put(alias, iaikCert);

            }
            return certMap;
        } catch(Exception e) {
            throw new IllegalStateException("error reading keystore", e);
        } finally {

        }


    }

    /**
     * This method checks a loaded certificate for being a signing certificate
     * @param cert the certificate
     * @return success if it is a signing certificate
     */
    private static boolean checkCertificate(X509Certificate cert) {
        boolean selected = false;
        try {

            Principal principal = cert.getSubjectDN();
            String name = principal.getName();
            ExtendedKeyUsage extendedKeyUsage = (ExtendedKeyUsage)cert.getExtension(ObjectID.certExt_ExtendedKeyUsage);
            cert.checkValidity();
            int count = 0;
            boolean [] keyUsage = cert.getKeyUsage();
            if (keyUsage != null) {
                if (keyUsage[0]) {
                    count++;
                }
            }



            if (name.startsWith("EMAIL")) {
                count++;
            }
            if (extendedKeyUsage != null) {
                ObjectID[] ids = extendedKeyUsage.getKeyPurposeIDs();
                for (ObjectID id : Arrays.asList(ids)) {
                    if (id.equals(ExtendedKeyUsage.clientAuth)) {
                        count++;
                    }

                }
            }
            selected = (count == 3);
        } catch (Exception e) {
            // do nothing
            selected = false;
        }
        return  selected;
    }
}
