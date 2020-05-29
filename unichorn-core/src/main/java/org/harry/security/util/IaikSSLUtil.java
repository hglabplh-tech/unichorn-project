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
// $Header: /IAIK-SSL/TLS13/TLS13/src/demo/DemoUtil.java 29    28.08.19 17:06 Dbratko $
//

package org.harry.security.util;

import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.security.random.MetaSeedGenerator;
import iaik.security.random.SeedGenerator;
import iaik.security.ssl.IaikProvider;
import iaik.security.ssl.KeyAndCert;
import iaik.security.ssl.KeyAndCertURL;
import iaik.security.ssl.OCSPCertStatusKeyAndCert;
import iaik.security.ssl.PSKCredential;
import iaik.security.ssl.SSLClientContext;
import iaik.security.ssl.SSLCommunication;
import iaik.security.ssl.SSLContext;
import iaik.security.ssl.SSLServerContext;
import iaik.security.ssl.SecurityProvider;
import iaik.security.ssl.Utils;
import iaik.utils.Util;
import iaik.x509.ocsp.CertID;
import iaik.x509.ocsp.CertStatus;
import iaik.x509.ocsp.ReqCert;
import iaik.x509.ocsp.SingleResponse;
import iaik.x509.ocsp.utils.ResponseGenerator;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import javax.crypto.spec.DHParameterSpec;


/**
 * Some basic utility methods.
 */
public class IaikSSLUtil {

  /** Debug flag for all demos */
  public final static boolean DEMO_DEBUG = true;

  private final static String PROVIDER_CLASS_NAME = "iaik.security.provider.IAIK";
  
  /**
   * URL of the OCSP responder for RSA signed server credentials.
   * (Used for the OCSP Certificate Status Request TLS extension demo). 
   */
  private final static String RSA_OCSP_RESPONDER_URL = "http://localhost:9991";
  
  /**
   * Port of the OCSP responder for RSA signed server credentials.
   * (Used for the OCSP Certificate Status Request TLS extension demo). 
   */
  private final static int RSA_OCSP_RESPONDER_PORT = 9991;
  
  /**
   * URL of the OCSP responder for DSA signed server credentials.
   * (Used for the OCSP Certificate Status Request TLS extension demo).
   */
  private final static String DSA_OCSP_RESPONDER_URL = "http://localhost:9992";
  
  /**
   * Port of the OCSP responder for DSA signed server credentials.
   * (Used for the OCSP Certificate Status Request TLS extension demo). 
   */
  private final static int DSA_OCSP_RESPONDER_PORT = 9992;

  /**
   * KeyStore type for demos ("IAIKKeyStore");
   */
  public final static String KEYSTORE_TYPE = "IAIKKeyStore";

  /**
   * Library version string.
   */
  public final static String VERSION = SSLContext.LIBRARY_VERSION_STRING;

  private final static String[] GREETING = {
    "*                                                                            *",
    "*          Welcome to the iSaSiLk Demo Programs                              *",
    "*                                                                            *",
    "* These simple programs show how to use the iSaSiLk library. Please see      *",
    "* the documentation and the source code for more information.                *",
    "*                                                                            *",
    "* We assume that you are using the IAIK JCE as your security provider        *",
    "* and that you may use IAIK ECCelerate(TM) as ECC security provider.         *",
    "*                                                                            *",
    "* NOTE that most of the demos require certificates to work, they are taken   *",
    "* from a keystore file that can be generated by calling demo.SetupKeyStore   *",
    "* or demo.ecc.SetupEccKeyStore.                                              *",
    "*                                                                            *",
    "",
  };

  private static boolean initialized = false;

  private IaikSSLUtil() {
    // empty
  }

  /** Perform a some initial setup to allow the demos to work */
  public synchronized static void initDemos() {
    if( initialized ) {
      return;
    }
    initialized = true;
    for( int i=0; i<GREETING.length; i++ ) {
      System.out.println(GREETING[i]);
    }
    initRandom();
    addIaikProvider();
  }

  /**
   * Add the IAIK JCE as a security provider. Note that to use a different
   * cryptographic provider it is <em>not</em> enough to just add it as a provider
   * see the SecurityProvider class for more information.
   *
   * @see SecurityProvider
   */
  public static void addIaikProvider() {
    addProvider(PROVIDER_CLASS_NAME);
  }

  public static void addProvider(String name) {
    try {
      Class clazz = Class.forName(name);
      Provider provider = (Provider)clazz.newInstance();
//      Security.addProvider(provider);
      Security.insertProviderAt(provider, 1);
    } catch (ClassNotFoundException ex) {
      System.out.println("Provider IAIK not found. Add iaik_jce.jar or iaik_jce_full.jar to your classpath.");
      System.out.println("If you are going to use a different provider please take a look at Readme.html!");
      System.exit(0);
    } catch (Exception ex) {
      System.out.println("Error adding provider:");
      ex.printStackTrace(System.err);
      System.exit(0);
    }
  }

  /**
   * Setup the random number generator for a quick start.
   * THIS IS NOT SECURE AND SHOULD BE USED FOR DEMO PURPOSES ONLY.
   * ANY CRYPTOGRAPHIC KEY DERIVED IN THIS WAY IS WEAK AND NO STRONGER THAN 20 BIT!!!
   */
  public static void initRandom() {
    System.out.println("Quick-starting random number generator (not for use in production systems!)...");
    Random random = new Random();
    byte[] seed = new byte[20];
    random.nextBytes(seed);
    MetaSeedGenerator.setSeed(seed);
    SeedGenerator.setDefault(MetaSeedGenerator.class);
  }
  




  /**
   * Wait for the user to press the return key on System.in.
   */
  public static void waitKey() {
    try {
      System.out.println("Hit the <RETURN> key.");
      do {
        System.in.read();
      } while( System.in.available() > 0 );
    } catch( IOException e ) {
      // ignore
    }
  }

  public static void sleep(int millis) {
    try {
      Thread.sleep(millis);
    } catch( InterruptedException e ) {
      // ignore
    }
  }

  public static void close(Socket s) {
    if( s == null ) {
      return;
    }
    try {
      s.close();
    } catch( IOException e ) {
      // ignore
    }
  }

  public static void close(ServerSocket s) {
    if( s == null ) {
      return;
    }
    try {
      s.close();
    } catch( IOException e ) {
      // ignore
    }
  }

  public static void close(OutputStream s) {
    if( s == null ) {
      return;
    }
    try {
      s.close();
    } catch( IOException e ) {
      // ignore
    }
  }

  public static void close(InputStream s) {
    if( s == null ) {
      return;
    }
    try {
      s.close();
    } catch( IOException e ) {
      // ignore
    }
  }

  public static void closec(SSLCommunication s) {
    if( s == null ) {
      return;
    }
    try {
      s.close();
    } catch( IOException e ) {
      // ignore
    }
  }

  public static String versionToString(int version) {
    switch( version ) {
    case SSLContext.VERSION_NOT_CONNECTED:
      return "(no secure connection established)";
    case SSLContext.VERSION_SSL20:
      return "SSL 2.0";
    case SSLContext.VERSION_SSL30:
      return "SSL 3.0";
    case SSLContext.VERSION_TLS10:
      return "TLS 1.0";
    case SSLContext.VERSION_TLS11:
      return "TLS 1.1";  
    case SSLContext.VERSION_TLS12:
      return "TLS 1.2";    
    default:
      return "Unknown protocol version " + (version >> 8) + "." + (version & 0xff);
    }
  }

  public static int parseInt(String s, int def) {
    if( s == null ) {
      return def;
    }
    try {
      return Integer.parseInt(s);
    } catch( NumberFormatException e ) {
      return def;
    }
  }
  

  /** 
   * Check if the class with the specified name is available 
   * 
   * @param className the name of the class to be checked for availability
   *
   * @return <code>true</code> if the class with the given name is available;
   *         <code>false</code> if it is not available
   */
  public static boolean isClassAvailable(String className) {
    try {
      Class clazz = Class.forName(className);
      return (clazz != null);
    } catch( Throwable e ) {
      return false;
    }
  }
  
  /**
   * Gets an ECC supporting IAIK SecurityProvider. Depending on its presence in
   * the classpath, either the new (ECCelerate) or old (IAIK-ECC) library is returned.
   * 
   * @return an ECC supporting IAIK SecurityProvider, or <code>null</code> if no
   *         IAIK ECC library is in the classpath
    * @throws Exception if no IAIK ECC Provider is available
   */
  public static SecurityProvider getEccSecurityProvider() throws Exception {
    
    IaikProvider iaikEccProvider;
    Class eccelerateProviderCl = null;
    String jdkVersion = getJDKVersion();
    if ((jdkVersion != null) && (jdkVersion.compareTo("1.6") >= 0)) {
      try {
        eccelerateProviderCl = Class.forName("iaik.security.ec.provider.ECCelerate");
      } catch (Throwable t) {
        // ignore; try old IAIK-ECC library
      }
    }  
    if (eccelerateProviderCl != null) {
      // new IAIK-ECC library
      Provider eccProvider = (Provider)eccelerateProviderCl.newInstance();
      Security.insertProviderAt(eccProvider, 1);
      iaikEccProvider = (IaikProvider)Class.forName("iaik.security.ssl.ECCelerateProvider").newInstance();
      try {
        // for the demos we disable SP80057 security strength recommendation checks
        Method[] methods = eccelerateProviderCl.getDeclaredMethods();
        Method method = eccelerateProviderCl.getDeclaredMethod("enforceSP80057Recommendations", new Class[] {boolean.class});
        method.invoke(eccelerateProviderCl, new Object[] { Boolean.FALSE });
      } catch (Throwable t) {
        // ignore; run with SP80057 recommendations enforced
      }
      try {
        // set default compression format to uncompressed
        Class pointEncodersCl = null;
        pointEncodersCl = Class.forName("iaik.security.ec.common.PointEncoders");
        Method method = pointEncodersCl.getDeclaredMethod("setDefaultPointEncoder", new Class[] {pointEncodersCl});
        Field field = pointEncodersCl.getDeclaredField("UNCOMPRESSED");
        Object obj = field.get(pointEncodersCl);
        method.invoke(pointEncodersCl, new Object[] { obj });
      } catch (Throwable t) {
        System.out.println("Warning: could not set \"uncompressed\" as default compression format for ECCelerate: " + t.toString());
      }
      try {
        // set default domain parameter encoding as OID
        Class ecParameterSpecCl = null;
        ecParameterSpecCl = Class.forName("iaik.security.ec.common.ECParameterSpec");
        Method method = ecParameterSpecCl.getDeclaredMethod("setDefaultOIDEncoding", new Class[] {boolean.class});
        method.invoke(ecParameterSpecCl, new Object[] { Boolean.TRUE });
      } catch (Throwable t) {
        System.out.println("Warning: could not set oid as default demoan parameter encoding for ECCelerate: " + t.toString());
      }
    } else if (isClassAvailable("iaik.security.ecc.provider.ECCProvider")) {
      // old IAIK-ECC library   
      
      iaikEccProvider = (IaikProvider)Class.forName("iaik.security.ssl.IaikEccProvider").newInstance();
      try {
        // set default domain parameter encoding as OID
        Class ecdsaParameterCl = null;
        ecdsaParameterCl = Class.forName("iaik.security.ecc.ecdsa.ECDSAParameter");
        Method method = ecdsaParameterCl.getDeclaredMethod("setDefaultOIDEncoding", new Class[] {boolean.class});
        method.invoke(ecdsaParameterCl, new Object[] { Boolean.TRUE });
      } catch (Throwable t) {
        System.out.println("Warning: could not set oid as default demoan parameter encoding for IAIK_ECC: " + t.toString());
      }
    } else {
      throw new Exception("Cannot install ECC SecurityProvider!");
    }
    SecurityProvider.setSecurityProvider(iaikEccProvider);
    return iaikEccProvider;
  }
  
  /**
   * Gets the version number of the current JDK.
   * 
   * @return the JDK version number
   */
  static public String getJDKVersion() {
    return (String)System.getProperty("java.version");
  }
  
}
