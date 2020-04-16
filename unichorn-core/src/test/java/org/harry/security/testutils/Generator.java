package org.harry.security.testutils;

import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.*;
import iaik.x509.X509Certificate;
import iaik.x509.X509ExtensionException;
import iaik.x509.extensions.*;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Random;

public class Generator {
    public static PrivateKey pk;
    public static X509Certificate createCertificate() throws NoSuchAlgorithmException {
        System.out.println("initialize....");
        boolean forSigning = true;
        AlgorithmID algorithm = (AlgorithmID)AlgorithmID.sha3_384WithRSAEncryption.clone();
        // Now create the certificates
        Name issuer = new Name();
        issuer.addRDN(ObjectID.country, "DE");
        issuer.addRDN(ObjectID.organization , "Unichorn GmbH");
        issuer.addRDN(ObjectID.organizationalUnit , "Signazure Dev, Team");
        issuer.addRDN(ObjectID.emailAddress , "harry@glab.org");


        Name subject = new Name();
        subject.addRDN(ObjectID.country, "DE");
        subject.addRDN(ObjectID.organization , "Unichorn GmbH");
        subject.addRDN(ObjectID.organizationalUnit , "Signazure Dev, Team");
        subject.addRDN(ObjectID.emailAddress , "harry@glab.org");

        System.out.println("gen keypair....");
        KeyPair pair = generateKeyPair("RSA", 2048);
        pk = pair.getPrivate();

        // create a new certificate
        X509Certificate cert = new X509Certificate();
        System.out.println("make cert....");
        try {
            // set the values
            cert.setSerialNumber(new BigInteger(20, new Random()));
            cert.setSubjectDN(subject);
            cert.setPublicKey(pair.getPublic());
            cert.setIssuerDN(issuer);

            GregorianCalendar date = new GregorianCalendar();
            // not before now
            cert.setValidNotBefore(date.getTime());

            if (issuer.equals(subject)) {
                // CA certificate
                date.add(Calendar.YEAR, 6);
                BasicConstraints basicConstraints = new BasicConstraints(true);
                cert.addExtension(basicConstraints);
                KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
                cert.addExtension(keyUsage);
            } else {
                date.add(Calendar.YEAR, 5);
                KeyUsage keyUsage = null;
                if (forSigning) {
                    keyUsage = new KeyUsage(KeyUsage.digitalSignature |
                            KeyUsage.nonRepudiation);
                } else {
                    if (pair.getPublic().getAlgorithm().equalsIgnoreCase("ESDH")) {
                        keyUsage = new KeyUsage(KeyUsage.keyAgreement) ;
                    } else {
                        keyUsage = new KeyUsage(KeyUsage.keyEncipherment);
                    }
                }
                cert.addExtension(keyUsage);
                AuthorityKeyIdentifier authID = new AuthorityKeyIdentifier();
                authID.setKeyIdentifier(null);
                cert.addExtension(authID);
                GeneralNames generalNames = new GeneralNames();
                generalNames.addName(new GeneralName(GeneralName.rfc822Name, "smimetest@harryglab.com"));
                SubjectAltName subjectAltName = new SubjectAltName(generalNames);
                cert.addExtension(subjectAltName);
            }
            String explicitText = "This certificate may be used for testing purposes only";
            PolicyQualifierInfo policyQualifier = new PolicyQualifierInfo(null, null, explicitText);
            PolicyInformation[] policyInformations =
                    { new PolicyInformation(new ObjectID("1.3.6.1.4.1.2706.2.2.4.1.1.1.1"),
                            new PolicyQualifierInfo[] { policyQualifier }) };
            CertificatePolicies certPolicies = new CertificatePolicies(policyInformations);

            SubjectKeyIdentifier subjectKeyID = new SubjectKeyIdentifier(cert.getPublicKey());
            cert.addExtension(subjectKeyID);

            cert.addExtension(certPolicies);
            cert.setValidNotAfter(date.getTime());
            // and sign the certificate
            System.out.println("sign cert....");
            cert.sign(algorithm , pair.getPrivate());
            System.out.println("ready....");
        } catch (CertificateException ex) {
            throw new RuntimeException("Error creating the certificate: "+ex.getMessage());
        } catch (InvalidKeyException ex) {
            throw new RuntimeException("Error creating the certificate: "+ex.getMessage());
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("Error creating the certificate: "+ex.getMessage());
        } catch (X509ExtensionException ex) {
            throw new RuntimeException("Error adding extension: "+ex.getMessage());
        } catch (CodingException ex) {
            throw new RuntimeException("Error adding SubjectKeyIdentifier extension: "+ex.getMessage());
        }
        return cert;
    }

    public static KeyPair generateKeyPair(String algorithm, int bits)
            throws NoSuchAlgorithmException {

        KeyPairGenerator generator = null;
        try {
            generator = KeyPairGenerator.getInstance(algorithm, "IAIK");
        } catch (NoSuchProviderException ex) {
            throw new NoSuchAlgorithmException("Provider IAIK not found!");
        }
        generator.initialize(bits);
        KeyPair kp = generator.generateKeyPair();
        return kp;
    }

}
