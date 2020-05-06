// Copyright (C) 2002 IAIK
// http://jce.iaik.tugraz.at
//
// Copyright (C) 2003 Stiftung Secure Information and 
//                    Communication Technologies SIC
// http://jce.iaik.tugraz.at
//
// All rights reserved.
//
// This source is provided for inspection purposes and recompilation only,
// unless specified differently in a contract with IAIK. This source has to
// be kept in strict confidence and must not be disclosed to any third party
// under any circumstances. Redistribution in source and binary forms, with
// or without modification, are <not> permitted in any case!
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.
//
// $Header: /IAIK-CMS/current/src/demo/keystore/SetupCMSKeyStore.java 32    12.07.12 15:57 Dbratko $
// $Revision: 32 $
//

package org.harry.security.util;


import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.*;
import iaik.asn1.structures.PolicyQualifierInfo;
import iaik.cms.Utils;
import iaik.security.ec.common.ECStandardizedParameterFactory;
import iaik.security.ec.provider.ECCelerate;
import iaik.security.provider.IAIK;
import iaik.utils.Util;
import iaik.x509.SimpleChainVerifier;
import iaik.x509.X509Certificate;
import iaik.x509.X509ExtensionException;
import iaik.x509.extensions.*;
import org.harry.security.util.certandkey.KeyStoreTool;
import sun.security.x509.X509CertImpl;

import java.io.*;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;

import static org.harry.security.util.CertificateWizzard.isCertificateSelfSigned;
import static org.harry.security.util.CertificateWizzard.setOCSPUrl;


/**
 * Creates a default KeyStore in the current working directory.
 * These keys are used by many demos included in IAIK-JCE.
 * The aliases and the password for accessing the keys and
 .
 *
 *
 * 
 * @author Dieter Bratko
 */
public class GenerateKeyStore implements CertGeneratorConstants {


  // the keylength of the CA certificate shall be 1024
  private final static int CA_KEYLENGTH = 2048;

  // the key store to create
  KeyStore key_store;
  // the file where the key store shall be saved
  String keystore_file;
  // takes the existing keys from the KeyStore and only creates new certificates
  boolean create_only_certificates = true;

  // the private keys
  
  // CA keys
  KeyPair ca_dsa = null;
  KeyPair ca_rsa = null;
  KeyPair ca_ecc = null;

  // Intermediate Keys
  KeyPair inter_dsa = null;
  KeyPair inter_rsa = null;
  KeyPair inter_ecc = null;
  
  // RSA for signing
  KeyPair rsa512_sign = null;
  KeyPair rsa1024_sign = null;
  KeyPair rsa2048_sign = null;
  // RSA for encrypting
  KeyPair rsa512_crypt = null;
  KeyPair rsa1024_crypt = null;
  KeyPair rsa1024_crypt_ = null;
  KeyPair rsa2048_crypt = null;

  // DSA signing
  KeyPair dsa512 = null;
  KeyPair dsa1024 = null;
  // DSA with SHA224
  KeyPair dsa2048 = null;
  // DSA with SHA256
  KeyPair dsa3072 = null;
  
  // DH key exchange
  KeyPair esdh512 = null;
  KeyPair esdh1024 = null;
  KeyPair esdh1024_ = null;
  KeyPair esdh2048 = null;
  KeyPair ssdh1024 = null;
  KeyPair ssdh1024_ = null;

  // ECC for signing
  KeyPair eccKey = null;
  KeyPair eccMaster = null;

    KeyPair rsaKey = null;
    KeyPair rsaMaster = null;
  
  // TSP Server
  KeyPair tsp_server = null;

  // create RSA keys and certificates
  boolean create_rsa;
  // create DSA keys and certificates
  boolean create_dsa;
  // create DSA SHA-2 keys and certificates
  boolean create_dsa_sha2;
  // create ESDH keys and certificates
  boolean create_esdh;
  // create SSDH keys and certificates
  boolean create_ssdh;
  // create TSP server key and certificate
  boolean create_tspserver;

  final ConfigReader.MainProperties properties;
  private boolean create_ecc;


  /**
   * Default Constructor.
   */
  public GenerateKeyStore(ConfigReader.MainProperties properties) {
    create_rsa = true;
    create_dsa = true;
    create_ecc = true;
    create_dsa_sha2 = ((create_dsa) && (Utils.getIaikProviderVersion() >= 3.18));
    create_esdh = create_ssdh = Utils.isClassAvailable("iaik.security.dh.ESDHPublicKey");
    create_tspserver = false;
    this.properties = properties;
  }

  /**
   * Generate a KeyPair using the specified algorithm with the given size.
   *
   * @param algorithm the algorithm to use
   * @param bits the length of the key (modulus) in bits
   * @return the KeyPair
   */
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

  /**
   * Creates a certificate from the given values.
   *
   * @param subject the subject of the certificate
   * @param publicKey the public key to include
   * @param issuer the issuer of the certificate
   * @param privateKey the private key for signing the certificate
   * @param algorithm the signature algorithm to use
   * @param keyID the key id for the AuthotityKeyIdentifier extension
   * @param forSigning if the certificate to be created shall be used for signing or encryption
   * @param tspServer whether to create a TSP server certificate
   *
   * @return the certificate just created
   */
  public static X509Certificate createCertificate(Name subject, PublicKey publicKey,
      Name issuer, PrivateKey privateKey, AlgorithmID algorithm, byte[] keyID,
      boolean forSigning, boolean tspServer) {

    // create a new certificate
    X509Certificate cert = new X509Certificate();

    try {
      // set the values
      cert.setSerialNumber(new BigInteger(20, new Random()));
      cert.setSubjectDN(subject);
      cert.setPublicKey(publicKey);
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
        setOCSPUrl(cert, "http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/ocsp");
      } else {
        date.add(Calendar.YEAR, 5);
        KeyUsage keyUsage = null;
        if (forSigning) {
          keyUsage = new KeyUsage(KeyUsage.digitalSignature |
                                  KeyUsage.nonRepudiation);
          if (tspServer) {
            // certificate for time stamp server
            ObjectID [] ids = new ObjectID[2];
            ids[0]  = ExtendedKeyUsage.timeStamping;
            ids[1]  = ExtendedKeyUsage.ocspSigning;

            ExtendedKeyUsage extKeyUsage = new ExtendedKeyUsage(ids);
            extKeyUsage.setCritical(true);
            cert.addExtension(extKeyUsage);
          }
        } else {
          if (publicKey.getAlgorithm().equalsIgnoreCase("ESDH")) {
            keyUsage = new KeyUsage(KeyUsage.keyAgreement) ;
          } else {
            keyUsage = new KeyUsage(KeyUsage.keyEncipherment);
          }
        }
        cert.addExtension(keyUsage);
        AuthorityKeyIdentifier authID = new AuthorityKeyIdentifier();
        authID.setKeyIdentifier(keyID);
        cert.addExtension(authID);
        GeneralNames generalNames = new GeneralNames();
        generalNames.addName(new GeneralName(GeneralName.rfc822Name, "smimetest@harryglab.com"));
        SubjectAltName subjectAltName = new SubjectAltName(generalNames);
        cert.addExtension(subjectAltName);
        setOCSPUrl(cert, "http://localhost:8080/unichorn-responder-1.0-SNAPSHOT/rest/ocsp");
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
      cert.sign(algorithm ,privateKey);
    } catch (CertificateException ex) {
      throw new RuntimeException("Error creating the certificate: "+ex.getMessage());
    } catch (InvalidKeyException ex) {
      throw new RuntimeException("Error creating the certificate: "+ex.getMessage());
    } catch (NoSuchAlgorithmException ex) {
      throw new RuntimeException("Error creating the certificate: "+ex.getMessage());
    } catch (X509ExtensionException ex) {
      throw new RuntimeException("Error adding extension: "+ex.getMessage());
    } catch (CodingException | MalformedURLException ex) {
      throw new RuntimeException("Error adding SubjectKeyIdentifier extension: "+ex.getMessage());
    }
    return cert;
  }

  /**
   * Load or create a KeyStore and initialize it.
   */
  public void initializeKeyStore() {

    BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
    String line;

    try {
      // default directory is the current user dir

      File ks = new File(properties.getKeystorePath()).getAbsoluteFile();
      keystore_file = ks.getAbsolutePath();

      create_only_certificates = false;
      // KeyStore does already exist
      if (ks.exists()) {
        ks.delete();
      }
      key_store = KeyStoreTool.initStore("PKCS12", properties.getKeystorePass());
      if (create_only_certificates) {
        // take private keys from existing KeyStore
        FileInputStream fis = null;
        try {
          fis = new FileInputStream(ks);
          key_store = KeyStoreTool.loadStore(fis, properties.getKeystorePass().toCharArray(), "PKCS12");
        } finally {
          if (fis != null) {
            try {
              fis.close();
            } catch (IOException ex) {
              // ignore
            }
          }
        }
      }
      else {
        // create a new KeyStore
        key_store.load(null, null);
      }

    } catch (Exception ex) {
      System.out.println("Error creating new IAIK KeyStore!");
      throw new RuntimeException("Error creating new KeyStore: "+ex.getMessage());
    }
  }

  /**
   * Save the KeyStore to disk.
   */
  public void saveKeyStore() {
    FileOutputStream os = null;
    try {
      // write the KeyStore to disk
      os = new FileOutputStream(keystore_file);
      key_store.store(os, properties.getKeystorePass().toCharArray());

    } catch (Exception ex) {
      System.out.println("Error saving KeyStore!");
      ex.printStackTrace();
    } finally {
      if (os != null) {
        try {
          os.close();
        } catch (IOException ex) {
          // ignore
        }
      }
    }
  }

  /**
   * Generates a key pair for a curve with a certain name
   *
   * @param bitlength
   *          the bitlength of the domain parameters to be used
   * @return the generated key pair
   */
  protected KeyPair generateKeyPairECC(final int bitlength) {
    try {
      final SecureRandom random = SecureRandom.getInstance("SHA512PRNG-SP80090", IAIK.getInstance());;
      final AlgorithmParameterSpec params = ECStandardizedParameterFactory
              .getParametersByBitLength(bitlength);

      System.out.println();
      System.out.println("Using the following EC domain parameters: ");
      System.out.println(params);
      System.out.println();

      final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", ECCelerate.getInstance());
      kpg.initialize(params, random);

      return kpg.generateKeyPair();
    } catch (final Exception e) {
      // should not occur SecureRandom.getInstance("SHA512PRNG-SP80090", IAIK.getInstance());
      e.printStackTrace();

      return null;
    }
  }

  /**
   * Creates a simple, self-signed X.509 certificate.
   *
   * @param privKey private key
   * @param pubKey public key
   * @param cNameSuffix suffix for subject identifier
   * @param issuer the issuers name
   *          the key pair used to generate the certificate
   * @return the generated X509Certificate
   */
  X509Certificate createCertificateECC(final PrivateKey privKey, final PublicKey pubKey, String cNameSuffix, Name issuer)
          throws InvalidKeyException, NoSuchAlgorithmException, CertificateException {
    // creating a self signed test certificate
    final Name subject = new Name();
    subject.addRDN(ObjectID.country, properties.getCountry());
    subject.addRDN(ObjectID.organization, properties.getOrganization());
    subject.addRDN(ObjectID.organizationalUnit, properties.getUnit());
    subject.addRDN(ObjectID.commonName, properties.getCommonName() + cNameSuffix);
    if (issuer == null) {
      issuer = subject;
    }
    final X509Certificate cert = new X509Certificate();

    cert.setSerialNumber(BigInteger.valueOf(0x1234L));
    cert.setSubjectDN(subject);
    cert.setPublicKey(pubKey);
    cert.setIssuerDN(issuer);

    // set the certificate to be valid not before now
    final GregorianCalendar date = new GregorianCalendar();
    cert.setValidNotBefore(date.getTime());

    date.add(Calendar.MONTH, 6);
    cert.setValidNotAfter(date.getTime());

    // add the X.509 extensions
    System.out.println("Signing certificate ...");
    cert.sign(AlgorithmID.ecdsa, privKey);

    return cert;
  }


  /**
   * Adds the private key and the certificate chain to the key store.
   *
   * @param keyPair the key pair with the private key to be added
   * @param chain the certificate chain to be added
   * @param alias the alias for the keystore entry
   *
   * @exception KeyStoreException if an error occurs when trying to add the key
   */
  public void addToKeyStore(KeyPair keyPair, X509Certificate[] chain, String alias) throws KeyStoreException {
    KeyStoreTool.addKey(key_store,keyPair.getPrivate(), properties.getKeystorePass().toCharArray(), chain, alias);
  }

  /**
   * Returns a KeyPair form the KeyStore.
   *
   * @return the KeyPair of the given type
   *
   * @exception Exception if some error occurs
   */
  private KeyPair getKeyPair(String type) throws Exception {
    Tuple<PrivateKey, X509Certificate[]>tuple = KeyStoreTool.getKeyEntry(key_store,type, properties.getKeystorePass().toCharArray());
    PublicKey pubKey = tuple.getSecond()[0].getPublicKey();
    return new KeyPair(pubKey, tuple.getFirst());
  }

  /**
   * Get all private keys from the KeyStore.
   */
  private void getPrivateKeys() {
    // RSA
    try {
      ca_rsa = getKeyPair(CA_RSA);
      // for signing
      rsa512_sign = getKeyPair(RSA_512_SIGN);
      rsa1024_sign = getKeyPair(RSA_1024_SIGN);
      rsa2048_sign = getKeyPair(RSA_2048_SIGN);
      // for encrypting
      rsa512_crypt = getKeyPair(RSA_512_CRYPT);
      rsa1024_crypt = getKeyPair(RSA_1024_CRYPT);
      rsa1024_crypt_ = getKeyPair(RSA_1024_CRYPT_);
      rsa2048_crypt = getKeyPair(RSA_2048_CRYPT);
    } catch (Exception ex) {
      System.out.println("Unable to get RSA keys from KeyStore: " + ex.toString());
      create_rsa = false;
    }
    // DSA
    try {
      ca_dsa = getKeyPair(CA_DSA);
      dsa512 = getKeyPair(DSA_512);
      dsa1024 = getKeyPair(DSA_1024);
    } catch (Exception ex) {
      System.out.println("Unable to get DSA keys from KeyStore: " + ex.toString());
      create_dsa = false;
    }
    // DSA with SHA-2
    try {
      dsa2048 = getKeyPair(DSA_2048);
      dsa3072 = getKeyPair(DSA_3072);
    } catch (Exception ex) {
      System.out.println("Unable to get DSA SHA-2 keys from KeyStore: " + ex.toString());
      create_dsa_sha2 = false;
    }
    // ESDH
    try {
      esdh512 = getKeyPair(ESDH_512);
      esdh1024 = getKeyPair(ESDH_1024);
      esdh1024_ = getKeyPair(ESDH_1024_);
      esdh2048 = getKeyPair(ESDH_2048);
    } catch (Exception ex) {
      System.out.println("Unable to get ESDH keys from KeyStore: " + ex.toString());
      create_esdh = false;
    }
    // SSDH
    try {
      ssdh1024 = getKeyPair(SSDH_1024);
      ssdh1024_ = getKeyPair(SSDH_1024_);
    } catch (Exception ex) {
      System.out.println("Unable to get SSDH keys from KeyStore: " + ex.toString());
      create_ssdh = false;
    }
    // TSP server
    try {
      tsp_server = getKeyPair(TSP_SERVER);
    } catch (Exception ex) {
      System.out.println("Unable to get TSP server key from KeyStore: " + ex.toString());
      create_tspserver = false;
    }
  }

  /**
   * Generates new prviate keys.
   */
  public void generatePrivateKeys() {
    try {
  	  // first create the KeyPairs
  	  if (create_rsa) {
  	    try {
          System.out.println("generate RSA KeyPair for CA certificate ["+CA_KEYLENGTH+" bits]...");
  	      ca_rsa = generateKeyPair("RSA", CA_KEYLENGTH);
  	      inter_rsa = generateKeyPair("RSA", CA_KEYLENGTH);
          System.out.println("Generate RSA signing keys...");
          System.out.println("generate RSA KeyPair for a test certificate [512 bits]...");
    	  rsa512_sign = generateKeyPair("RSA", 2048);
          System.out.println("generate RSA KeyPair for a test certificate [1024 bits]...");
    	  rsa1024_sign = generateKeyPair("RSA", 2048);
          System.out.println("generate RSA KeyPair for a test certificate [2048 bits]...");
    	  rsa2048_sign = generateKeyPair("RSA", 2048);
       	  System.out.println("Generate RSA encryption keys...");
          System.out.println("generate RSA KeyPair for a test certificate [512 bits]...");
    	  rsa512_crypt = generateKeyPair("RSA", 2048);
          System.out.println("generate RSA KeyPair for a test certificate [1024 bits]...");
    	  rsa1024_crypt = generateKeyPair("RSA", 2048);
    	  System.out.println("generate second RSA KeyPair for a test certificate [1024 bits]...");
    	  rsa1024_crypt_ = generateKeyPair("RSA", 2048);
          System.out.println("generate RSA KeyPair for a test certificate [2048 bits]...");
    	  rsa2048_crypt = generateKeyPair("RSA", 2048);
    	  rsaKey = generateKeyPair("RSA", 4096);
    	  rsaMaster = generateKeyPair("RSA", 4096);
  	    } catch (NoSuchAlgorithmException ex) {
          create_rsa = false;
          System.out.println("No implementation for RSA! RSA certificates are not created!\n");
  	    }
  	  }

      if (create_dsa) {
  	    try {
          System.out.println("generate DSA KeyPair for CA certificate ["+CA_KEYLENGTH+" bits]...");
  	      ca_dsa = generateKeyPair("DSA", CA_KEYLENGTH);
          inter_dsa = generateKeyPair("DSA", CA_KEYLENGTH);
          System.out.println("generate DSA KeyPair for a test certificate [512 bits]...");
    	  dsa512 = generateKeyPair("DSA", 1024);
          System.out.println("generate DSA KeyPair for a test certificate [1024 bits]...");
    	  dsa1024 = generateKeyPair("DSA", 1024);
  	    } catch (NoSuchAlgorithmException ex) {
          create_dsa = false;
          System.out.println("No implementation for DSA! DSA certificates are not created!\n");
  	    }
      }

      if (create_dsa_sha2) {
        try {
          System.out.println("generate DSA SHA-224 KeyPair for a test certificate [2048 bits]...");
          dsa2048 = generateKeyPair("SHA224withDSA", 3072);
          System.out.println("generate DSA SHA-256 KeyPair for a test certificate [3072 bits]...");
          dsa3072 = generateKeyPair("SHA256withDSA", 3072);
        } catch (NoSuchAlgorithmException ex) {
          create_dsa = false;
          System.out.println("No implementation for SHA2-DSA! SHA2-DSA certificates are not created!\n");
        }
      }

      if (create_esdh) {
        try {
          System.out.println("generate ESDH KeyPair for a test certificate [512 bits]...");
    	  esdh512 = generateKeyPair("ESDH", 1024);
          System.out.println("generate ESDH KeyPair for a test certificate [1024 bits]...");
    	  esdh1024 = generateKeyPair("ESDH", 1024);
    	  System.out.println("generate ESDH KeyPair for a test certificate [1024 bits]...");
    	  esdh1024_ = generateKeyPair("ESDH", 1024);
          System.out.println("generate ESDH KeyPair for a test certificate [2048 bits]...");
    	  esdh2048 = generateKeyPair("ESDH", 1024);
  	    } catch (NoSuchAlgorithmException ex) {
          create_esdh = false;
          System.out.println("No implementation for ESDH! ESDH certificates are not created!\n");
  	    }
  	  }

  	  if (create_ssdh) {
        try {
          System.out.println("generate SSDH KeyPair for a test certificate [1024 bits]...");
          // key alg id the same as ESDH
    	  ssdh1024 = generateKeyPair("ESDH", 1024);
    	  System.out.println("generate SSDH KeyPair for a test certificate [1024 bits]...");
    	  ssdh1024_ = generateKeyPair("ESDH", 1024);
        } catch (NoSuchAlgorithmException ex) {
          create_ssdh = false;
          System.out.println("No implementation for SSDH! SSDH certificates are not created!\n");
  	    }
  	  }

  	  if (create_ecc) {
        ca_ecc = generateKeyPairECC( 571);
  	    eccKey = generateKeyPairECC( 571);
  	    eccMaster = generateKeyPairECC( 571);

      }

      if (create_tspserver) {
        try {
          System.out.println("generate RSA KeyPair for a tsp server test certificate [1024 bits]...");
          tsp_server = generateKeyPair("RSA", 1024);
        } catch (NoSuchAlgorithmException ex) {
          create_tspserver = false;
          System.out.println("No implementation for RSA! TSP server certificate not created!\n");
        }
      }

    } catch (Exception ex) {
      System.out.println("Exception: "+ex);
    }
  }

  /**
   * Generates the certificates.
   */
  public void generateCertificates() {

    try {

      // Now create the certificates
      Name issuer = new Name();
      issuer.addRDN(ObjectID.country,
              properties.getCountry());
      issuer.addRDN(ObjectID.organization ,properties.getOrganization());
      issuer.addRDN(ObjectID.organizationalUnit ,properties.getUnit());

      Name subject = new Name();
      subject.addRDN(ObjectID.country, properties.getCountry());
      subject.addRDN(ObjectID.organization , properties.getOrganization());
      subject.addRDN(ObjectID.organizationalUnit ,properties.getUnit());

      //
      // create self signed CA certs
      //
      X509Certificate caRSA = null;
      X509Certificate caDSA = null;
      X509Certificate interRSA = null;
      X509Certificate interDSA = null;
      X509Certificate[] chain = new X509Certificate[1];
      // for verifying the created certificates
      SimpleChainVerifier verifier = new SimpleChainVerifier();

      if (create_rsa) {
        KeyUsage usage = CertificateWizzard.certUsage();
        issuer.addRDN(ObjectID.commonName ,properties.getCommonName());
        System.out.println("create self signed RSA CA certificate...");
        caRSA = CertificateWizzard.createCertificate(issuer,
                ca_rsa.getPublic(),
                issuer,
                ca_rsa.getPrivate(),
                (AlgorithmID)AlgorithmID.sha256WithRSAEncryption.clone(),
                null,
                usage);
        // verify the self signed certificate
          boolean selfSigned = isCertificateSelfSigned(caRSA);
          if (!selfSigned) {
              throw new IllegalStateException("certificate should be self signed");
          }
          caRSA.verify();
        // set the CA cert as trusted root
        verifier.addTrustedCertificate(caRSA);
        chain[0] = caRSA;
        addToKeyStore(ca_rsa, chain, CA_RSA);
        issuer.removeRDN(ObjectID.commonName);
        chain = new X509Certificate[2];
        issuer.addRDN(ObjectID.commonName ,properties.getCommonName() + "_Inter");
        System.out.println("create self signed RSA CA certificate...");
        interRSA =  CertificateWizzard.createCertificate(subject,
                inter_rsa.getPublic(),
                issuer,
                ca_rsa.getPrivate(),
                (AlgorithmID)AlgorithmID.sha256WithRSAEncryption.clone(),
                null,
                usage);
        chain[0] = interRSA;
        // verify the self signed certificate
        selfSigned = isCertificateSelfSigned(chain[0]);
        if (selfSigned) {
          throw new IllegalStateException("certificate should be self signed");
        }
        caRSA.verify();
        // set the CA cert as trusted root
        verifier.addTrustedCertificate(caRSA);
        chain[1] = caRSA;
        addToKeyStore(ca_rsa, chain, CA_RSA + "_Inter");
        issuer.removeRDN(ObjectID.commonName);
      }

      if (create_dsa) {
        issuer.addRDN(ObjectID.commonName ,properties.getCommonName()+"DSA");
        System.out.println("create self signed DSA CA certificate...");
        caDSA = createCertificate(issuer,
                                  ca_dsa.getPublic(),
                                  issuer,
                                  ca_dsa.getPrivate(),
                                  (AlgorithmID)AlgorithmID.dsaWithSHA.clone(),
                                  null,
                                  true,
                                  false);
        // verify the self signed certificate
        caDSA.verify();
        // set the CA cert as trusted root
        verifier.addTrustedCertificate(caDSA);
        chain[0] = caDSA;
        addToKeyStore(ca_dsa, chain, CA_DSA);
        issuer.removeRDN(ObjectID.commonName);
      }

      //
      // create certificates
      //
      chain = new X509Certificate[3];

      // create a RSA certificate
      if (create_rsa) {
        KeyUsage usage = CertificateWizzard.signUsage();
        issuer.addRDN(ObjectID.commonName ,properties.getCommonName() + "RSA");
        SubjectKeyIdentifier subjectKeyID = (SubjectKeyIdentifier)caRSA.getExtension(SubjectKeyIdentifier.oid);
        // 512
         // for signing
        System.out.println("Create RSA demo certificates to be used for signing...");

        // 512
        subject.addRDN(ObjectID.commonName, "RSA 512 bit Demo Signing Certificate");
        System.out.println("create 512 bit RSA demo certificate...");
        chain[0] =  CertificateWizzard.createCertificate(subject,
                rsa512_sign.getPublic(),
                issuer,
                inter_rsa.getPrivate(),
                (AlgorithmID)AlgorithmID.sha256WithRSAEncryption.clone(),
                null,
                usage);

        chain[1] = interRSA;
        chain[2] = caRSA;
        // and verify the chain
        verifier.verifyChain(chain);
        addToKeyStore(rsa512_sign, chain, RSA_512_SIGN);
        subject.removeRDN(ObjectID.commonName);

        // 1024

        subject.addRDN(ObjectID.commonName ,"RSA 1024 bit Demo Signing Certificate");
        System.out.println("create 1024 bit RSA demo certificate...");
        chain[0] = createCertificate(subject,
                                     rsa1024_sign.getPublic(),
                                     issuer,
                                     ca_rsa.getPrivate(),
                                     (AlgorithmID)AlgorithmID.sha1WithRSAEncryption.clone(),
                                     subjectKeyID.get(),
                                     true,
                                     false);
        chain[1] = caRSA;
        verifier.verifyChain(chain);
        addToKeyStore(rsa1024_sign, chain, RSA_1024_SIGN);
        subject.removeRDN(ObjectID.commonName);

        // 2048

        subject.addRDN(ObjectID.commonName ,"RSA 2048 bit Demo Signing Certificate");
        System.out.println("create 2048 bit RSA demo certificate...");
        chain[0] = createCertificate(subject,
                                     rsa2048_sign.getPublic(),
                                     issuer,
                                     ca_rsa.getPrivate(),
                                     (AlgorithmID)AlgorithmID.sha1WithRSAEncryption.clone(),
                                     subjectKeyID.get(),
                                     true,
                                     false);
        chain[1] = caRSA;
          boolean selfSigned = isCertificateSelfSigned(chain[0]);
          if (selfSigned) {
              throw new IllegalStateException("certificate should NOT be self signed");
          }
        verifier.verifyChain(chain);

        addToKeyStore(rsa2048_sign, chain, RSA_2048_SIGN);
        subject.removeRDN(ObjectID.commonName);

        // for encrypting
        System.out.println("Create RSA demo certificates to be used for encryption...");
        // 512
        subject.addRDN(ObjectID.commonName, "RSA 512 bit Demo Encryption Certificate");
        System.out.println("create 512 bit RSA demo certificate...");
        chain[0] = createCertificate(subject,
                                     rsa512_crypt.getPublic(),
                                     issuer,
                                     ca_rsa.getPrivate(),
                                     (AlgorithmID)AlgorithmID.sha1WithRSAEncryption.clone(),
                                     subjectKeyID.get(),
                                     false,
                                     false);
        chain[1] = caRSA;
        // and verify the chain
        verifier.verifyChain(chain);
        addToKeyStore(rsa512_crypt, chain, RSA_512_CRYPT);
        subject.removeRDN(ObjectID.commonName);

        // 1024

        subject.addRDN(ObjectID.commonName ,"RSA 1024 bit Demo Encryption Certificate");
        System.out.println("create 1024 bit RSA demo certificate...");
        chain[0] = createCertificate(subject,
                                     rsa1024_crypt.getPublic(),
                                     issuer,
                                     ca_rsa.getPrivate(),
                                     (AlgorithmID)AlgorithmID.sha1WithRSAEncryption.clone(),
                                     subjectKeyID.get(),
                                     false,
                                     false);
        chain[1] = caRSA;
        verifier.verifyChain(chain);
        addToKeyStore(rsa1024_crypt, chain, RSA_1024_CRYPT);

        System.out.println("create second 1024 bit RSA demo Encryption certificate...");
        chain[0] = createCertificate(subject,
                                     rsa1024_crypt_.getPublic(),
                                     issuer,
                                     ca_rsa.getPrivate(),
                                     (AlgorithmID)AlgorithmID.sha1WithRSAEncryption.clone(),
                                     subjectKeyID.get(),
                                     false,
                                     false);
        chain[1] = caRSA;
        verifier.verifyChain(chain);
        addToKeyStore(rsa1024_crypt_, chain, RSA_1024_CRYPT_);
        subject.removeRDN(ObjectID.commonName);

        // 2048

        subject.addRDN(ObjectID.commonName ,"RSA 2048 bit Demo Encryption Certificate");
        System.out.println("create 2048 bit RSA demo certificate...");
        chain[0] = createCertificate(subject,
                                     rsa2048_crypt.getPublic(),
                                     issuer,
                                     ca_rsa.getPrivate(),
                                     (AlgorithmID)AlgorithmID.sha1WithRSAEncryption.clone(),
                                     subjectKeyID.get(),
                                     false,
                                     false);
        chain[1] = caRSA;
        verifier.verifyChain(chain);
        addToKeyStore(rsa2048_crypt, chain, RSA_2048_CRYPT);
        subject.removeRDN(ObjectID.commonName);
        issuer.removeRDN(ObjectID.commonName);
      }

      // create a DSA test certificate
      if (create_dsa) {
        issuer.addRDN(ObjectID.commonName ,properties.getCommonName() + "CA RSA");
        // 512
        subject.addRDN(ObjectID.commonName ,"DSA 512 bit Demo Certificate");
        System.out.println("create 512 bit DSA demo certificate...");
        SubjectKeyIdentifier subjectKeyID = (SubjectKeyIdentifier)caDSA.getExtension(SubjectKeyIdentifier.oid);
        chain[0] = createCertificate(subject,
                                     dsa512.getPublic(),
                                     issuer,
                                     ca_dsa.getPrivate(),
                                     (AlgorithmID)AlgorithmID.dsaWithSHA.clone(),
                                     subjectKeyID.get(),
                                     true,
                                     false);
        subject.removeRDN(ObjectID.commonName);
        chain[1] = caDSA;
        verifier.verifyChain(chain);

        addToKeyStore(dsa512, chain, DSA_512);
        // 1024
        subject.addRDN(ObjectID.commonName ,"DSA 1024 bit Demo Certificate");
        System.out.println("create 1024 bit DSA demo certificate...");
        chain[0] = createCertificate(subject,
                                     dsa1024.getPublic(),
                                     issuer,
                                     ca_dsa.getPrivate(),
                                     (AlgorithmID)AlgorithmID.dsaWithSHA.clone(),
                                     subjectKeyID.get(),
                                     true,
                                     false);
        subject.removeRDN(ObjectID.commonName);
        chain[1] = caDSA;
        verifier.verifyChain(chain);
        addToKeyStore(dsa1024, chain, DSA_1024);
        issuer.removeRDN(ObjectID.commonName);
      }

      // create SHA-2 DSA test certificates
      if (create_dsa_sha2) {
        issuer.addRDN(ObjectID.commonName ,properties.getCommonName() + "DSA CA");
        // 2048
        subject.addRDN(ObjectID.commonName ,"DSA SHA-224 2048 bit Test Certificate");
        System.out.println("create 2048 bit SHA224withDSA test certificate...");
        SubjectKeyIdentifier subjectKeyID = (SubjectKeyIdentifier)caDSA.getExtension(SubjectKeyIdentifier.oid);
        chain[0] = createCertificate(subject, dsa2048.getPublic(),
              issuer, ca_dsa.getPrivate(), AlgorithmID.dsaWithSHA, subjectKeyID.get(), true, false);
        subject.removeRDN(ObjectID.commonName);
        chain[1] = caDSA;
        verifier.verifyChain(chain);
        addToKeyStore(dsa2048, chain, DSA_2048);

        // 3072
        subject.addRDN(ObjectID.commonName ,"DSA SHA-256 3072 bit Test Certificate");
        System.out.println("create 3072 bit SHA256withDSA test certificate...");
        chain[0] = createCertificate(subject, dsa3072.getPublic(),
              issuer, ca_dsa.getPrivate(), AlgorithmID.dsaWithSHA, subjectKeyID.get(), true, false);
        subject.removeRDN(ObjectID.commonName);
        chain[1] = caDSA;
        verifier.verifyChain(chain);
        addToKeyStore(dsa3072, chain, DSA_3072);
        issuer.removeRDN(ObjectID.commonName);
      }


      // create a ESDH test certificate
      if (create_esdh) {
        issuer.addRDN(ObjectID.commonName ,properties.getCommonName() + "DSA CA");
        // 512
        subject.addRDN(ObjectID.commonName ,"ESDH 512 bit Demo Certificate");
        System.out.println("create 512 bit ESDH demo certificate...");
        SubjectKeyIdentifier subjectKeyID = (SubjectKeyIdentifier)caDSA.getExtension(SubjectKeyIdentifier.oid);
        chain[0] = createCertificate(subject,
                                     esdh512.getPublic(),
                                     issuer,
                                     ca_dsa.getPrivate(),
                                     (AlgorithmID)AlgorithmID.dsaWithSHA.clone(),
                                     subjectKeyID.get(),
                                     false,
                                     false);
        subject.removeRDN(ObjectID.commonName);
        chain[1] = caDSA;
        verifier.verifyChain(chain);
        addToKeyStore(esdh512, chain, ESDH_512);
        // 1024
        subject.addRDN(ObjectID.commonName ,"ESDH 1024 bit Demo Certificate 1");
        System.out.println("create 1024 bit ESDH demo certificate...");
        chain[0] = createCertificate(subject,
                                     esdh1024.getPublic(),
                                     issuer,
                                     ca_dsa.getPrivate(),
                                     (AlgorithmID)AlgorithmID.dsaWithSHA.clone(),
                                     subjectKeyID.get(),
                                     false,
                                     false);
        subject.removeRDN(ObjectID.commonName);
        chain[1] = caDSA;
        verifier.verifyChain(chain);
        addToKeyStore(esdh1024, chain, ESDH_1024);
        // 1024
        subject.addRDN(ObjectID.commonName ,"ESDH 1024 bit Demo Certificate 2");
        System.out.println("create second 1024 bit ESDH demo certificate...");
        chain[0] = createCertificate(subject,
                                     esdh1024_.getPublic(),
                                     issuer,
                                     ca_dsa.getPrivate(),
                                     (AlgorithmID)AlgorithmID.dsaWithSHA.clone(),
                                     subjectKeyID.get(),
                                     false,
                                     false);
        subject.removeRDN(ObjectID.commonName);
        chain[1] = caDSA;
        verifier.verifyChain(chain);
        addToKeyStore(esdh1024_, chain, ESDH_1024_);
        // 2048
        subject.addRDN(ObjectID.commonName ,"ESDH 2048 bit Demo Certificate");
        System.out.println("create 2048 bit ESDH demo certificate...");
        chain[0] = createCertificate(subject,
                                     esdh2048.getPublic(),
                                     issuer,
                                     ca_dsa.getPrivate(),
                                     (AlgorithmID)AlgorithmID.dsaWithSHA.clone(),
                                     subjectKeyID.get(),
                                     false,
                                     false);
        subject.removeRDN(ObjectID.commonName);
        chain[1] = caDSA;
        verifier.verifyChain(chain);
        addToKeyStore(esdh2048, chain, ESDH_2048);
        issuer.removeRDN(ObjectID.commonName);
      }

          // create a SSDH test certificate
      if (create_ssdh) {
        issuer.addRDN(ObjectID.commonName ,properties.getCommonName() + "DSA CA");
        SubjectKeyIdentifier subjectKeyID = (SubjectKeyIdentifier)caDSA.getExtension(SubjectKeyIdentifier.oid);
        // 1024
        subject.addRDN(ObjectID.commonName ,"SSDH 1024 bit Demo Certificate 1");
        System.out.println("create 1024 bit SSDH demo certificate...");
        chain[0] = createCertificate(subject,
                                     ssdh1024.getPublic(),
                                     issuer,
                                     ca_dsa.getPrivate(),
                                     (AlgorithmID)AlgorithmID.dsaWithSHA.clone(),
                                     subjectKeyID.get(),
                                     false,
                                     false);
        subject.removeRDN(ObjectID.commonName);
        chain[1] = caDSA;
        verifier.verifyChain(chain);
        addToKeyStore(ssdh1024, chain, SSDH_1024);
        // 1024
        subject.addRDN(ObjectID.commonName ,"SSDH 1024 bit Demo Certificate 2");
        System.out.println("create second 1024 bit SSDH demo certificate...");
        chain[0] = createCertificate(subject,
                                     ssdh1024_.getPublic(),
                                     issuer,
                                     ca_dsa.getPrivate(),
                                     (AlgorithmID)AlgorithmID.dsaWithSHA.clone(),
                                     subjectKeyID.get(),
                                     false,
                                     false);
        subject.removeRDN(ObjectID.commonName);
        chain[1] = caDSA;
        verifier.verifyChain(chain);
        addToKeyStore(ssdh1024_, chain, SSDH_1024_);
        issuer.removeRDN(ObjectID.commonName);
      }

      if (create_tspserver) {
        issuer.addRDN(ObjectID.commonName ,properties.getCommonName() + "RSA CA");
        SubjectKeyIdentifier subjectKeyID = (SubjectKeyIdentifier)caRSA.getExtension(SubjectKeyIdentifier.oid);
        subject.addRDN(ObjectID.commonName ,"IAIK TSP Demo Server Certificate");
        System.out.println("create 1024 bit RSA TSP demo server certificate...");
        chain[0] = createCertificate(subject,
                                     tsp_server.getPublic(),
                                     issuer,
                                     ca_rsa.getPrivate(),
                                     (AlgorithmID)AlgorithmID.sha1WithRSAEncryption.clone(),
                                     subjectKeyID.get(),
                                     true,
                                     true);
        chain[1] = caRSA;
        verifier.verifyChain(chain);
        addToKeyStore(tsp_server, chain, TSP_SERVER);
        subject.removeRDN(ObjectID.commonName);

      }

      if (create_ecc) {
        issuer.addRDN(ObjectID.commonName ,properties.getCommonName() +"ECC CA" );
        System.out.println("create self signed ECC CA certificate...");
        X509Certificate caECC = createCertificate(issuer,
                ca_ecc.getPublic(),
                issuer,
                ca_ecc.getPrivate(),
                (AlgorithmID)AlgorithmID.ecdsa.clone(),
                null,
                true,
                false);
        // verify the self signed certificate
        caECC.verify();
        // set the CA cert as trusted root
        verifier.addTrustedCertificate(caECC);
        chain[0] = caECC;
        addToKeyStore(ca_ecc, chain, "CA_ECC");
        issuer.removeRDN(ObjectID.commonName);


        issuer.addRDN(ObjectID.commonName ,properties.getCommonName() + "ECC");
        SubjectKeyIdentifier subjectKeyID = (SubjectKeyIdentifier)caECC.getExtension(SubjectKeyIdentifier.oid);
        // 512
        // for signing
        System.out.println("Create ECC demo certificates to be used for signing...");

        // 512
        subject.addRDN(ObjectID.commonName, "ECC 571 bit Demo Signing Certificate");
        subject.removeRDN(ObjectID.organization);
        subject.addRDN(ObjectID.organization, "Signers crazy");

        System.out.println("create 571 bit ECC demo certificate...");
        chain[0] = createCertificate(subject,
                eccKey.getPublic(),
                issuer,
                ca_ecc.getPrivate(),
                (AlgorithmID)AlgorithmID.ecdsa.clone(),
                subjectKeyID.get(),
                true,
                false);
        chain[0].writeTo(new FileOutputStream(new File("./signerCert.cer").getAbsoluteFile()));
          PrivateKeyStore store = new PrivateKeyStore(properties, false);
          store.addToStore(chain[0], eccKey.getPrivate(), "hglabplh");
        chain[1] = caECC;

        // and verify the chain
        verifier.verifyChain(chain);
        addToKeyStore(eccKey, chain, "EC_SIGNER");
        subject.removeRDN(ObjectID.commonName);
          subject.removeRDN(ObjectID.organization);
          subject.addRDN(ObjectID.organization, "Signers master");
          subject.addRDN(ObjectID.commonName, "ECC 571 bit Master Master Certificate");
          System.out.println("create 571 bit ECC Master certificate...");
          chain[0] = createCertificate(subject,
                  eccMaster.getPublic(),
                  issuer,
                  ca_ecc.getPrivate(),
                  (AlgorithmID)AlgorithmID.ecdsa.clone(),
                  subjectKeyID.get(),
                  true,
                  false);
          chain[1] = caECC;

          // and verify the chain
          verifier.verifyChain(chain);
          addToKeyStore(eccMaster, chain, "EC_MASTER");
          subject.removeRDN(ObjectID.commonName);
          issuer.addRDN(ObjectID.commonName ,properties.getCommonName() +"ECC CA" );
          chain[0] = createCertificate(subject,
                  rsaKey.getPublic(),
                  issuer,
                  ca_rsa.getPrivate(),
                  (AlgorithmID)AlgorithmID.sha256WithRSAEncryption.clone(),
                  subjectKeyID.get(),
                  true,
                  false);
          chain[0].writeTo(new FileOutputStream(new File("./signerCertRSA.cer").getAbsoluteFile()));

          store.addToStore(chain[0], rsaKey.getPrivate(), "hglabplhRSA");
          chain[1] = caRSA;

          // and verify the chain
          verifier.verifyChain(chain);
          addToKeyStore(rsaKey, chain, "RSA_SIGNER");
          subject.removeRDN(ObjectID.commonName);
          subject.removeRDN(ObjectID.organization);
          subject.addRDN(ObjectID.organization, "Signers master");
          subject.addRDN(ObjectID.commonName, "ECC 571 bit Master Master Certificate");
          System.out.println("create 571 bit ECC Master certificate...");
          chain[0] = createCertificate(subject,
                  rsaMaster.getPublic(),
                  issuer,
                  ca_rsa.getPrivate(),
                  (AlgorithmID)AlgorithmID.sha256WithRSAEncryption.clone(),
                  subjectKeyID.get(),
                  true,
                  false);
          chain[1] = caRSA;

          // and verify the chain
          verifier.verifyChain(chain);
          store.writeToStore();
          addToKeyStore(rsaMaster, chain, "RSA_MASTER");
          subject.removeRDN(ObjectID.commonName);


          issuer.addRDN(ObjectID.commonName ,properties.getCommonName() + "ECC");
          subjectKeyID = (SubjectKeyIdentifier)caRSA.getExtension(SubjectKeyIdentifier.oid);
          // 512
          // for signing
          System.out.println("Create ECC demo certificates to be used for signing...");

          subject.addRDN(ObjectID.commonName, "ECC 571 bit Demo Signing Certificate");

      }

      System.out.println("\nCertificates created!");
 
    } catch (Exception ex) {
      System.out.println("Exception: "+ex);
      ex.printStackTrace();
      return;
    }
  }
  

  
  /**
   * Reads the next line from the given BufferedReader.
   * 
   * @param reader the reader from which to read the line
   * 
   * @return the line just read
   * 
   * @throws IOException if an I/O error occurs
   */
  private final static String readLine(BufferedReader reader) throws IOException {
    String line = reader.readLine();
    if (line != null) {
      line = line.trim();
    } else {
      line = "";
    }
    return line;
  }
  

}