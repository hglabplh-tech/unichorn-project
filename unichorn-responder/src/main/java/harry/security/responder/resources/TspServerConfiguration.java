//Copyright (C) 2002 IAIK
//http://jce.iaik.at
//
//Copyright (C) 2003 - 2010 Stiftung Secure Information and 
//                          Communication Technologies SIC
//http://www.sic.st
//
//All rights reserved.
//
//Redistribution and use in source and binary forms, with or without
//modification, are permitted provided that the following conditions
//are met:
//1. Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//2. Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
//THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
//ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
//FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
//OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
//LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
//OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
//SUCH DAMAGE.
//
//$Header: /TSP/current/demo/src/demo/tsp/config/TspServerConfiguration.java 21    1.12.16 15:53 Dbratko $
//$Revision: 21 $
//

package harry.security.responder.resources;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.cms.SecurityProvider;
import iaik.pkcs.PKCSException;
import iaik.pkcs.PKCSParsingException;
import iaik.pkcs.pkcs12.CertificateBag;
import iaik.pkcs.pkcs12.PKCS12;
import iaik.tsp.Accuracy;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.X509ExtensionInitException;
import iaik.x509.extensions.ExtendedKeyUsage;
import iaik.x509.extensions.KeyUsage;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.KeyStoreTool;

/**
 * This demo class provides the configuration of a TspServer.
 * <p>
 * The server configuration is read from file <code>ServerConfiguration.properties</code>
 * that has to reside somewhere in the classpath.
 * <br>
 * The following configuration settings may be specified:
 * <ol>
 *   <li>
 *       SERVERPORT: the port the server shall listen for TSP requests (default: 318)
 *   </li>
 *   <li>
 *       MAX_TIME_OUT: the socket timeout (default: 60000)
 *   </li>
 *   <li>
 *       OIDSTRING: the TSA policy oid
 *   </li>
 *   <li>
 *       SET_ACCURACY: whether the <code>Accuracy</code> field in the <code>TimeStampResp</code> should be set or not (default)
 *   </li>   
 *   <li>
 *       ACCURACY_SECONDS: the accuracy seconds value (only meaningful if the <code>Accuracy</code> field shall be set)
 *   </li>
 *   <li>
 *       ACCURACY_MILLIS: the accuracy millis value (only meaningful if the <code>Accuracy</code> field shall be set)
 *   </li>
 *   <li>
 *       ACCURACY_MICROS: the accuracy micros value (only meaningful if the <code>Accuracy</code> field shall be set)
 *   </li>
 *   <li>
 *       HASH_ALGORITHM: the hash algorithm to be used
 *   </li> 
 *   <li>
 *       SIGNATURE_ALGORITHM: the signature algorithm to be used; if not specified the signature algorithm is
 *                            calculated from the hash algorithm and the key algorithm
 *   </li> 
 *   <li>
 *       ADD_SHA1_CERTID: whether to also include SHA-1 ESSCertID if ESSCertIDv2 is used
 *   </li> 
 * </ol>
 * <br>
 * The following configuration settings may be used to specify the file (either by url or name)
 * from which to read the TSA key/certificate from a PKCS#12 or (more generally) Java KeyStore
 * file:
 * <ol>          
 *   <li>
 *       PKCS12URL: the PKCS#12 file url from which to read TSA key/cert
 *   </li>
 *   <li>
 *       PKCS12FILE: the PKCS#12 file name from which to read TSA key/cert (maybe used to specify the TSA key/cert
 *                                                                          by file name instead of specifying
 *                                                                          it by url)
 *   </li>   
 *   <li>
 *       PKCS12PWD: the password for the PKCS#12 file 
 *   </li>      
 *   <li>
 *       KS_URL: the KeyStore file url from which to read TSA key/cert (maybe used to specify the TSA key/cert
 *                                                                      by KeyStore file url instead of specifying
 *                                                                      it by PKCS#12 file url) 
 *   </li>
 *   <li>
 *       KS_FILE: the KeyStore file name from which to read TSA key/cert (maybe used to specify the TSA key/cert
 *                                                                       by KeyStore file name instead of specifying
 *                                                                       it by KeyStore file url)
 *   </li>   
 *   <li>
 *       KS_PWD: the password for the KeyStore file
 *   </li>  
 *   <li>
 *       KS_TYPE: the KeyStore type, default &quot;PKCS12&quot;
 *   </li> 
 *   <li>
 *       KS_PROVIDER: the KeyStore provider
 *   </li>  
 *   <li>
 *       KS_ALIAS: the KeyStore alias, name of the key
 *   </li>          
 * </ol>
 * The <code>PKCS12URL</code> or <code>PKCS12FILE</code> options may be used when the
 * TSA key/cert shall be read from a PKCS#12 file. e.g.:
 * <pre>
 * PKCS12URL=timeStampCert.p12
 * PKCS12PWD=topSecret
 * </pre>
 * or
 * <pre>
 * PKCS12FILE=D:/TSA/key/timeStampCert.p12
 * PKCS12PWD=topSecret
 * </pre>
 * The <code>KS_URL</code> and <code>KS_FILE</code> options also can be used to read TSA key/cert
 * from a PKCS#12 file but also allow to use alternative Java KeyStore formats (e.g. &quot;IAIKKeyStore&quot;,
 * &quot;JKS&quot;, &quot;IAIKKeyStore&quot;, &quot;PKCS11KeyStore&quot;,... .
 * <p>
 * For instance:
 * <pre>
 * KS_FILE=D:/TSA/key/timeStampCert.p12
 * KS_PWD=topSecret
 * KS_ALIAS=demo-tsa
 * KS_TYPE=PKCS12
 * KS_PROVIDER=IAIK
 * </pre>
 * or (for accessing a HSM key by using the IAIK PKCS11Provider)
 * <pre>
 * KS_FILE=eTPkcs11.dll
 * KS_PWD=112233
 * KS_ALIAS=demo-tsa
 * KS_TYPE=PKCS11KeyStore
 * </pre>
 * If <code>KS_ALIAS</code> is not specified the KeyStore is searched for a key/certificate that
 * is appropriate to be used for TimeStamp signing (contains a critical <code>ExtendedKeyUsagae</code>
 * extension with key purpose id <code>timeStamping</code> as required by RFC 3161). If the certificate
 * contains a <code>KeyUsage</code> extension this method also checks if the <code>KeyUsage</code> 
 * extension makes the certificate eligible for signing, i.e. if the <code>digitalSignature</code> or
 * <code>nonRepudiation</code> key usage bits are set. 
 */
public class TspServerConfiguration {

  /**
   * Default Configuration URL.
   */
  public static final String ConfigurationURL = "ServerConfiguration.properties";

  /**
   * The logger for this class.
   */
  protected static Log log = LogFactory.getLog(TspServerConfiguration.class);
  
  /**
   * Default hash algorithm.
   */
  private final static AlgorithmID DEFAULT_HASH_ALGORITHM = AlgorithmID.sha256;
  
  // property keys
  
  /**
   * Property key SERVERPORT.
   */
  private final static String PROP_SERVERPORT = "SERVERPORT";
  
  /**
   * Property key MAX_TIME_OUT.
   */
  private final static String PROP_MAX_TIME_OUT = "MAX_TIME_OUT";
  
  /**
   * Property key OIDSTRING (TSA policy oid).
   */
  private final static String PROP_OIDSTRING = "OIDSTRING";
  
  /**
   * Property key SET_ACCURACY (decides whether the <code>Accuracy</code> in the <code>TimeStampResp</code> should be set or not).
   */
  private final static String PROP_SET_ACCURACY = "SET_ACCURACY";
  
  /**
   * Property key ACCURACY_SECONDS.
   */
  private final static String PROP_ACCURACY_SECONDS = "ACCURACY_SECONDS";
  
  /**
   * Property key ACCURACY_MILLIS.
   */
  private final static String PROP_ACCURACY_MILLIS = "ACCURACY_MILLIS";
  
  /**
   * Property key ACCURACY_MICROS.
   */
  private final static String PROP_ACCURACY_MICROS = "ACCURACY_MICROS";
  
  /**
   * Property key PKCS12URL (PKCS#12 file url from which to read TSA key/cert).
   */
  private final static String PROP_PKCS12URL = "PKCS12URL";
  
  /**
   * Property key PKCS12FILE (PKCS#12 file from which to read TSA key/cert).
   */
  private final static String PROP_PKCS12FILE = "PKCS12FILE";
  
  /**
   * Property key PKCS12PWD (password for PKCS#12 file).
   */
  private final static String PROP_PKCS12PWD = "PKCS12PWD";
  
  /**
   * Property key KS_URL (KeyStore file url from which to read TSA key/cert).
   */
  private final static String PROP_KS_URL = "KS_URL";
  
  /**
   * Property key KS_FILE (KeyStore file from which to read TSA key/cert).
   */
  private final static String PROP_KS_FILE = "KS_FILE";
  
  /**
   * Property key KS_PWD (KeyStore password).
   */
  private final static String PROP_KS_PWD = "KS_PWD";
  
  /**
   * Property key KS_TYPE (KeyStore type, default "PKCS12").
   */
  private final static String PROP_KS_TYPE = "KS_TYPE";
  
  /**
   * Property key KS_PROVIDER (KeyStore provider).
   */
  private final static String PROP_KS_PROVIDER = "KS_PROVIDER";
  
  /**
   * Property key KS_ALIAS (KeyStore alias; name of the key).
   */
  private final static String PROP_KS_ALIAS = "KS_ALIAS";
  
  /**
   * Property key HASH_ALGORITHM (the hash algorithm to be used).
   */
  private final static String PROP_HASH_ALGORITHM = "HASH_ALGORITHM";
  
  /**
   * Property key SIGNATURE_ALGORITHM (if not specified the signature algorithm is
   * calculated from the hash algorithm and the key algorithm).
   */
  private final static String PROP_SIGNATURE_ALGORITHM = "SIGNATURE_ALGORITHM";
  
  /**
   * Property key ADD_SHA1_CERTID (whether to also include SHA-1 ESSCertID if ESSCertIDv2 is used).
   */
  private final static String PROP_ADD_SHA1_CERTID = "ADD_SHA1_CERTID";
  

  /**
   * The private key used for signing
   */
  private PrivateKey tsaPrivateKey_;

  /**
   * The certificate chain of the tsa
   */
  private X509Certificate[] tsaCertChain_;

  /**
   * The policy ObjectID of the TSA.
   */
  private ObjectID oid_;

  /**
   * The property file.
   */
  private Properties properties;

  /**
   * Indicates whether a accuracy is set or not.
   */
  private boolean setAccuracy_ = false;

  /**
   * The accuracy object.
   */
  private Accuracy accuracy_;

  /**
   * The used hash algorithm.
   */
  private AlgorithmID hashAlgorithm_ = DEFAULT_HASH_ALGORITHM;
  
  /**
   * The used signature algorithm (if not specified the signature algorithm is
   * calculated from the hash algorithm and the key algorithm).
   */
  private AlgorithmID signatureAlgorithm_;
  
  /**
   * Whether to also include SHA-1 ESSCertID if ESSCertIDv2 is used 
   * with another hash algorithm.
   */
  private boolean addSha1CertID_ = true;

  /**
   * The port where the tsa should listen
   */
  private int serverPort_ = -1;

  /**
   * The maximum timeout of the server 
   */
  private int maxTimeOut_ = 60000;

  /**
   * Default constructor
   */
  public TspServerConfiguration() {
    properties = new Properties();
  }

  /**
   * Loads the configuration from the specified <code>URL</code>.
   * 
   * @param url
   *          The <code>URL</code> of the property file. If this parameter is
   *          <code>null</code> the default location (ServerConfiguration.properties) will be used.
   * @throws IOException
   *           Thrown if the specified property is not in the classpath.
   * @throws TspServerConfigurationException
   *           Thrown if the PKCS#12 file could not be found or decrypted.
   */
  public void loadConfiguration(String url) throws IOException, TspServerConfigurationException {
    print();
    InputStream in;
    if (url == null) {
      in = getClass().getClassLoader().getResourceAsStream(ConfigurationURL);
      if (in == null) {
        throw new IOException("TcpIpServerConfiguration.properties file not found");
      }
    } else {
      in = getClass().getClassLoader().getResourceAsStream(url);
      if (in == null) {
        throw new IOException("Properties file \"" + url + "\" not found");
      }
    }

    properties.load(in);
    String oidString = properties.getProperty(PROP_OIDSTRING);

    String set_accuracy = properties.getProperty(PROP_SET_ACCURACY);

    if (set_accuracy != null && set_accuracy.equals("1"))
      setAccuracy_ = true;
    else
      setAccuracy_ = false;

    KeyStore store = KeyStoreTool.loadAppStore();
    Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
    tsaPrivateKey_ = keys.getFirst();
    tsaCertChain_ = keys.getSecond();
    if (setAccuracy_) {

      accuracy_ = new Accuracy();
      {
        String s_ACCURACY_SECONDS = properties.getProperty(PROP_ACCURACY_SECONDS);
        if (s_ACCURACY_SECONDS != null && s_ACCURACY_SECONDS.length() > 0) {
          int ACCURACY_SECONDS = Integer.parseInt(s_ACCURACY_SECONDS);
          accuracy_.setSeconds(ACCURACY_SECONDS);
        }

      {
        String s_ACCURACY_MILLIS = properties.getProperty(PROP_ACCURACY_MILLIS);
        if (s_ACCURACY_MILLIS != null && s_ACCURACY_MILLIS.length() > 0) {
          int ACCURACY_MILLIS = Integer.parseInt(s_ACCURACY_MILLIS);
          accuracy_.setMillis(ACCURACY_MILLIS);
        }
      }
      {
        String s_ACCURACY_MICROS = properties.getProperty(PROP_ACCURACY_MICROS);
        if (s_ACCURACY_MICROS != null && s_ACCURACY_MICROS.length() > 0) {
          int ACCURACY_MICROS = Integer.parseInt(s_ACCURACY_MICROS);
          accuracy_.setMicros(ACCURACY_MICROS);
        }
      }
    }

    String hash_algorithm = properties.getProperty(PROP_HASH_ALGORITHM);
    if (hash_algorithm != null) {
      AlgorithmID algID = AlgorithmID.getAlgorithmID(hash_algorithm);
      if (algID != null) {
        hashAlgorithm_ = algID;
      } else {
        hashAlgorithm_ = DEFAULT_HASH_ALGORITHM;
      }
    }

    String signatureAlgorithm = properties.getProperty(PROP_SIGNATURE_ALGORITHM);
    if (signatureAlgorithm != null) {
      signatureAlgorithm_ = AlgorithmID.getAlgorithmID(signatureAlgorithm);
    }

    String add_sha1CertID = properties.getProperty(PROP_ADD_SHA1_CERTID);
    if (add_sha1CertID != null && add_sha1CertID.equals("1"))
      addSha1CertID_ = true;
    else
      addSha1CertID_ = false;

    String port = properties.getProperty(PROP_SERVERPORT);
    if (port != null) {
      serverPort_ = Integer.parseInt(port);
    }

    String timeOut = properties.getProperty(PROP_MAX_TIME_OUT);
    if (timeOut != null) {
      maxTimeOut_ = Integer.parseInt(timeOut);
    }


    } else {

    }
    if (tsaPrivateKey_ == null) {
      throw new TspServerConfigurationException("No TSA key loaded!");
    }
    if (tsaCertChain_ == null) {
      throw new TspServerConfigurationException("No TSA certificate loaded!");
    }
    oid_ = new ObjectID(oidString);
  }
  
  /**
   * Reads TSA key and certificate from a PKCS#12 file.
   * 
   * @param pkcs12Url the url to the PKCS#12 file
   * @param pkcs12File the file name of the PKCS#12 file (if <code>pkcs12Url</code> is not set or does not work)
   * @param pkcs12Pwd the password for the PKCS#12 file
   * 
   * @throws IOException if the PKCS#12 file cannot be read
   * @throws PKCSParsingException if the PKCS#12 file cannot be parsed
   * @throws TspServerConfigurationException if an configuration error occurs
   */
  private void readKeyAndCertFromPkcs12File(String pkcs12Url, String pkcs12File, char[] pkcs12Pwd) 
    throws IOException, PKCSParsingException, TspServerConfigurationException {
    
    PKCS12 pkcs12 = null;
    InputStream inP12 = null;
    try {
      if (pkcs12Url != null) {
        log.debug("Loading TSA PKCS12 file from " + pkcs12Url);
        inP12 = getClass().getClassLoader().getResourceAsStream(pkcs12Url);
      }
      if (inP12 == null) {
        if (pkcs12File != null) {
          log.debug("Loading TSA PKCS12 file from " + pkcs12File);
          inP12 = new FileInputStream(pkcs12File);
        } else {
          throw new IOException("Can't load the pkcs12 file: " + pkcs12Url);
        }  
      }
      pkcs12 = new PKCS12(inP12);
    } finally {
      if (inP12 != null) {
        inP12.close();
      }
    }

    log.debug("Trying to decrypt PKCS12 file");
    try {
      pkcs12.decrypt(pkcs12Pwd);
    } catch (PKCSException pkcse) {
      throw new PKCSParsingException(pkcse.toString());
    }

    X509Certificate[] certs = CertificateBag.getCertificates(pkcs12.getCertificateBags());
    if (certs.length > 1) { 
      certs = Util.arrangeCertificateChain(certs, false);
    }  
    if (certs == null) {
      throw new PKCSParsingException("Could not arrange certificate chain!");
    }
    checkKeyUsage(certs[0]); 
    

    tsaCertChain_ = certs;
    tsaPrivateKey_ = pkcs12.getKeyBag().getPrivateKey();

  }
  
  /**
   * Reads TSA key and certificate from a KeyStore.
   * 
   * @param keyStoreUrl the url to the KeyStore file
   * @param keyStoreFile the name of the KeyStore file (if <code>keyStoreUrl</code> is not set or does not work)
   * @param keyStorePwd the KeyStore password
   * @param keyStoreType the KeyStore type (default: PKCS12)
   * @param keyStoreProvider the KeyStore provider (maybe <code>null</code>)
   * @param signatureAlgorithm the signature algorithm (may be <code>null</code>) 
   * 
   * @throws IOException if the KeyStore file cannot be read
   * @throws KeyStoreException if the KeyStore file cannot be parsed
   * @throws TspServerConfigurationException if an configuration error occurs
   */
  private void readKeyAndCertFromKeyStore(String keyStoreUrl, String keyStoreFile, char[] keyStorePwd,
      String keyName, String keyStoreType, String keyStoreProvider, String signatureAlgorithm) 
    throws IOException, KeyStoreException, TspServerConfigurationException {
    
    if (keyStoreType == null) {
      log.debug("keyStoreType not specified. Using default (\"PKCS12\"");
      keyStoreType = "PKCS12";
    }
    
    KeyStore keyStore = null;
    InputStream inKs = null;
    
    try {
      if (keyStoreUrl != null) {
        log.debug("Loading TSA KeyStore file from " + keyStoreUrl);
        if ((keyStoreProvider == null) && (keyStoreType.endsWith("PKCS11KeyStore"))) {
          try {
            keyStoreProvider = createPKCS11KeyStoreProvider(keyStoreUrl);
          } catch (KeyStoreException e) {
            if (keyStoreFile == null) {
              throw e;
            }
          }
        } else {
          inKs = getClass().getClassLoader().getResourceAsStream(keyStoreUrl);
        }  
      }
      if (inKs == null) {
        if (keyStoreFile != null) {
          log.debug("Loading TSA KeyStore file from " + keyStoreFile);
          if (keyStoreType.endsWith("PKCS11KeyStore")) {
            if (keyStoreProvider == null) {
              keyStoreProvider = createPKCS11KeyStoreProvider(keyStoreFile);
            }  
          } else {  
            inKs = new FileInputStream(keyStoreFile);
          }  
        }  
      }
      
      try {
        keyStore = (keyStoreProvider == null) ? 
          KeyStore.getInstance(keyStoreType) :
          KeyStore.getInstance(keyStoreType, keyStoreProvider);
        keyStore.load(inKs, keyStorePwd);
      } catch (Exception e) {
        throw new KeyStoreException("Error loading keystore: " + e.toString());
      }
      Enumeration aliases = keyStore.aliases();
      while (aliases.hasMoreElements()) {
        String alias = (String)aliases.nextElement();
        if ((keyName != null) && (!keyName.equals(alias))) {
          continue;
        }
        boolean throwExceptionOnError = ((keyName != null) || (!aliases.hasMoreElements()));
        Certificate[] certChain = keyStore.getCertificateChain(alias);
        if ((certChain == null) || (certChain.length == 0)) {
          if (!throwExceptionOnError) {
            continue;
          }
          throw new KeyStoreException("No certificate chain available for alias " + alias);
        }
        X509Certificate[] certs = null;
        try {
          certs = Util.convertCertificateChain(certChain);
        } catch (CertificateException e) {
          if (!throwExceptionOnError) {
            continue;
          }
          throw new KeyStoreException("Could not convert certificate chain!");
        }
        if (certs.length > 1) { 
          certs = Util.arrangeCertificateChain(certs, false);
        }  
        if (certs == null) {
          if (!throwExceptionOnError) {
            continue;
          }
          throw new KeyStoreException("Could not arrange certificate chain!");
        }
        try {
          checkKeyUsage(certs[0]); 
        } catch (TspServerConfigurationException e) {
          if (!throwExceptionOnError) {
            continue;
          }
          throw e;
        }
        Key key = null;
        try {
          key = keyStore.getKey(alias, keyStorePwd);
        } catch (Exception e) {
          if (!throwExceptionOnError) {
            continue;
          }
          throw new KeyStoreException("Error getting key for alias \"" + alias + "\": " + e.toString());
        }
        if (key == null) {
          if (!throwExceptionOnError) {
            continue;
          }
          throw new KeyStoreException("No key available for alias " + alias);
        }
        if (!(key instanceof PrivateKey)) {
          if (!throwExceptionOnError) {
            continue;
          }
          throw new KeyStoreException("No private key available for alias " + alias);
        }
        PrivateKey privateKey = (PrivateKey)key;; 
        if (signatureAlgorithm != null) {
          String keyAlgorithm = privateKey.getAlgorithm();
          if (keyAlgorithm == null) {
            keyAlgorithm = certs[0].getPublicKey().getAlgorithm();
          }
          if (!checkKey(keyAlgorithm, signatureAlgorithm)) {
            if (!throwExceptionOnError) {
              continue;
            }
            throw new KeyStoreException(keyAlgorithm + " key cannot be used with signature algorithm " + signatureAlgorithm + "!"); 
          }
        }
        tsaCertChain_ = certs;
        tsaPrivateKey_ = privateKey;
        if ((tsaCertChain_ != null) && (tsaPrivateKey_ != null)) {
          log.debug("Got TSA Certificate: " + tsaCertChain_[0].getSubjectDN());
          break;
        }  
      } 
      if (keyName != null) {
        if ((tsaCertChain_ == null) || (tsaPrivateKey_ == null)) {
             throw new KeyStoreException("No key/cert for alias " + keyName + " found in keystore " + keyStoreUrl + "!");           
        }
      }  
    } finally {
      if (inKs != null) {
        inKs.close();
      }
    }

  }
  
  /**
   * Create a IAIK PKCS#11 provider for reading the TSA key from a token keystore.
   * 
   * @param moduleName the name of the hardware module
   * @return the name of the PKCS#11 KeyStore provider just created
   * 
   * @throws KeyStoreException if the PKCS#11 KeyStore provider cannot be created
   */
  private final String createPKCS11KeyStoreProvider(String moduleName) throws KeyStoreException {
    // we assume that no PKCS#11 provider for the module has been installed yet
    // (otherwise we might search the installed providers if suitable for the requested module)
    String providerName = null;
    Properties pkcs11ProviderConfig = new Properties();
    pkcs11ProviderConfig.put("PKCS11_NATIVE_MODULE", moduleName);
    Class iaikPkcs11ProviderCl = null;
    try {
      iaikPkcs11ProviderCl = Class.forName("iaik.pkcs.pkcs11.provider.IAIKPkcs11");
      Constructor constructor = iaikPkcs11ProviderCl.getDeclaredConstructor(new Class[] {Properties.class});
      Provider iaikPKCS11 = (Provider)constructor.newInstance(new Object[] { pkcs11ProviderConfig });
      Security.addProvider(iaikPKCS11);
      providerName = iaikPKCS11.getName();
      
      try {
        // set PKCS#11 CMS SecurityProvider from <code>iaik_cms_demo.jar</code>
        Class pkcs11SecurityProviderCl = Class.forName("demo.cms.pkcs11.IaikPkcs11SecurityProvider");
        constructor = pkcs11SecurityProviderCl.getDeclaredConstructor(new Class[] {iaikPkcs11ProviderCl});
        SecurityProvider cmsPkcs11Provider = (SecurityProvider)constructor.newInstance(new Object[] { iaikPKCS11 });
        SecurityProvider.setSecurityProvider(cmsPkcs11Provider);
      } catch (Throwable t) {
        log.warn("Error setting CMS PKCS#11 SecurityProvider: " + t.toString());
      }
    } catch (Throwable t) {
      t.printStackTrace();
      throw new KeyStoreException("Cannot create PKCS#11 KeyStore provider: " + t.toString());
    }
    
    return providerName;
  }
  
  /**
   * Key algorithm names.
   */
  private final static String[] KEY_ALGORITHMS = { "RSA", "EC", "DSA" };
  /**
   * Checks if the given key (algorithm) may be used with the given signature algorithm.
   * 
   * @param keyAlgorithm the key to be checked
   * @param signatureAlgorithm signature algorithm
   * 
   * @return <code>true</code> if the key may be used with the signature algorithm;
   *         <code>false</code> if not 
   */
  private final static boolean checkKey(String keyAlgorithm, String signatureAlgorithm) {
    keyAlgorithm = keyAlgorithm.toUpperCase(Locale.US);
    signatureAlgorithm = signatureAlgorithm.toUpperCase(Locale.US);
    boolean foundMatch = false;
    for (int i = 0; i < KEY_ALGORITHMS.length; i++) {
      String keyAlg = KEY_ALGORITHMS[i];
      if ((keyAlgorithm.startsWith(keyAlg)) &&
          (signatureAlgorithm.indexOf(keyAlg) != -1)) {
        foundMatch = true;
        break;
      }  
    }
    return foundMatch;
  }
  
  /**
   * This method checks the <code>ExtendedKeyUsage</code> and <code>KeyUsage</code>
   * extensions of the TSA responder certificate.
   * <p>
   * This method checks if the given TSA responder certificate contains a 
   * critical <code>ExtendedKeyUsagae</code> extension with key purpose
   * id <code>timeStamping</code> as required by RFC 3161. If the certificate
   * contains a <code>KeyUsage</code> extension this method also checks if
   * the <code>KeyUsage</code> extension makes the certificate eligible
   * for signing, i.e. if the <code>digitalSignature</code> or
   * <code>nonRepudiation</code> key usage bits are set.
   * 
   * @param tsaCert
   *          The certificate of the TSA responder
   * @throws TspServerConfigurationException
   *           If the TSA certificate does not contain a critical <code>ExtendedKeyUsage</code> 
   *           extension with <code>timeStamping</code> key purpose id, or the certificate 
   *           does not contain a signing eligible KeyUsage extension (<code>digitalSignature</code>
   *           or <code>nonRepudiation</code>, or KeyUsage or ExtendedKeyUsage extension are present but cannot be parsed)
   */
  private static final void checkKeyUsage(X509Certificate tsaCert) throws TspServerConfigurationException {
      try {
        ExtendedKeyUsage extendedKeyUsage = (ExtendedKeyUsage)tsaCert.getExtension(ExtendedKeyUsage.oid);
        if (extendedKeyUsage == null) {
          throw new TspServerConfigurationException("TSA certificate does not contain ExtendedKeyUsage extension!");
        }
        if (extendedKeyUsage.isCritical() == false) {
          throw new TspServerConfigurationException("ExtendedKeyUsage extension of TSA certificate must be critical!");          
        }
        // check in this way to be compatible with IAIK-JCE versions < 4.0
        ObjectID[] keyPurposeIDs = extendedKeyUsage.getKeyPurposeIDs();
        boolean timeStampingSet = false;
        if (keyPurposeIDs != null) {
          for (int i = 0; i < keyPurposeIDs.length; i++) {
            if (ExtendedKeyUsage.timeStamping.equals(keyPurposeIDs[i])) {
              timeStampingSet = true;
              break;
            }
          }
        }
        if (timeStampingSet == false) {
          throw new TspServerConfigurationException("ExtendedKeyUsage extension of TSA certificate must contain timeStamping purpose id!");
        }
      } catch (final X509ExtensionInitException e) {
        throw new TspServerConfigurationException("Error parsing ExtendedKeyUsage extension of TSA certificate: " + e.toString());
      }
      try {
        KeyUsage keyUsage = (KeyUsage)tsaCert.getExtension(KeyUsage.oid);
        if (keyUsage != null) {
          
          if ((!keyUsage.isSet(KeyUsage.digitalSignature)) && (!keyUsage.isSet(KeyUsage.nonRepudiation))) {
            throw new TspServerConfigurationException("KeyUsage extension of TSA certificate not eligible for signing!");
          }
        }  
      } catch (final X509ExtensionInitException e) {
        throw new TspServerConfigurationException("Error parsing KeyUsage extension of TSA certificate: " + e.toString());
      }
   
  }


  /**
   * Returns the <code>PrivateKey</code>.
   * 
   * @return The <code>PrivateKey</code>.
   */
  public PrivateKey getPrivateKey() {
    return tsaPrivateKey_;
  }

  /**
   * Returns the <code>ObjectID</code>.
   * 
   * @return The <code>ObjectID</code>.
   */
  public ObjectID getObjectID() {
    return oid_;
  }

  
  /**
   * Returns the certificate chain of the TSA containing the TSA cert at index 0.
   * 
   * @return The certificate chain of the TSA containing the TSA cert at index 0.
   */
  public X509Certificate[] getTSACertChain() {
    return tsaCertChain_;
  }

  /**
   * Returns the port.
   * 
   * @return The port.
   */
  public int getServerPort() {
    return serverPort_;
  }

  /**
   * Returns whether the <code>Accuracy</code> in the <code>TimeStampResp</code> should be set or not.
   * 
   * @return True if the <code>Accuracy</code> should be set otherwise false.
   */
  public boolean setAccuracy() {
    return setAccuracy_;
  }

  /**
   * Returns the <code>Accuracy</code>.
   * 
   * @return The <code>Accuracy</code>.
   */
  public Accuracy getAccuracy() {
    return accuracy_;
  }

  /**
   * Returns the hash algorithm to be used for signing.
   * 
   * @return The hash <code>AlgorithmID</code>.
   */
  public AlgorithmID getHashAlgorithm() {
    return (AlgorithmID)hashAlgorithm_.clone();
  }
  
  /**
   * Returns the signature algorithm to be used for signing.
   * 
   * @return The signature <code>AlgorithmID</code>. Maybe <code>null</code> (in this case
   *         the signature algorithm is calculated from the hash algorithm and the key algorithm).
   */
  public AlgorithmID getSignatureAlgorithm() {
    AlgorithmID signatureAlgorithm = signatureAlgorithm_;
    if (signatureAlgorithm != null) {
      signatureAlgorithm = (AlgorithmID)signatureAlgorithm.clone();
    }
    return signatureAlgorithm;
  }
  
  /**
   * Returns whether to also include SHA-1 ESSCertID if
   * ESSCertIDv2 is used with another hash algorithm.
   * 
   * @return <code>true</code> to add SHA-2 ESSCertID if ESSCertIDv2
   *         is used with another hash algorithm,
   *         <code>false</code> to not add SHA-1 ESSCertID
   */
  public boolean getAddSha1CertID() {
    return addSha1CertID_;
  }

  /**
   * Returns the time out of the socket.
   * 
   * @return The time out.
   */
  public int getMaxTimeOut() {
    return maxTimeOut_;
  }

  private void print() {
    try {
      String[] reminderMessage = new String[] {
          "*****************************************************************************",
          "***                                                                       ***",
          "***        !!! This service is just for DEMONSTRATION purposes !!!        ***",
          "***               Commercial use of this demo is prohibited               ***",
          "***                                                                       ***",
          "*****************************************************************************", };
      for (int i = 0; i < reminderMessage.length; i++) {
        System.err.println(reminderMessage[i]);
      }
    } catch (Throwable th) {
      th.printStackTrace();
      // we go on, this should not keep applications from working
    }
  }
}