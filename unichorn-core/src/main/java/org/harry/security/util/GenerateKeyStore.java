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

  }

  /**
   * Generates the certificates.
   */
  public void generateCertificates() throws IOException {
  // 'TODO: next to look at

    FileOutputStream stream = new FileOutputStream(properties.getAttrCertPath());
    CertificateWizzard wizzard = new CertificateWizzard(properties, stream);
    KeyPair caKeys = wizzard.generateCA(properties.getCommonName(), true);
    KeyPair interKeys = wizzard.generateIntermediate(caKeys, properties.getCommonName(), true);
    wizzard.generateUser(interKeys, properties.getCommonName(), true);

    caKeys = wizzard.generateCA("NoPSS Cert Common", false);
    interKeys = wizzard.generateIntermediate(caKeys, "NoPSS Cert Common", false);
    wizzard.generateUser(interKeys, "NoPSS Cert Common", false);

    KeyStoreTool.storeKeyStore(wizzard.getStore(),
            new FileOutputStream(properties.getKeystorePath()), properties.getKeystorePass().toCharArray());
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