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
// $Header: /IAIK-SSL/TLS13/TLS13/src/demo/HtmlUtil.java 28    23.09.19 13:10 Dbratko $
//

package org.harry.security.util;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AVA;
import iaik.asn1.structures.Name;
import iaik.asn1.structures.RDN;
import iaik.security.ssl.CipherSuite;
import iaik.security.ssl.CipherSuiteList;
import iaik.security.ssl.Extension;
import iaik.security.ssl.ExtensionList;
import iaik.security.ssl.SecurityProvider;
import iaik.x509.V3Extension;

import java.io.BufferedReader;
import java.io.CharArrayReader;
import java.io.CharArrayWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

/**
 * Some HTML formatting utility methods used by the client and server info
 * programs.
 *

 */
public class HtmlUtil {

  public final static Boolean FALSE = Boolean.FALSE;
  public final static Boolean TRUE = Boolean.TRUE;

  private HtmlUtil() {
    // empty
  }

  public static void printCertificate(PrintWriter writer, X509Certificate certificate) {
    iaik.x509.X509Certificate cert = (iaik.x509.X509Certificate)certificate;

    writer.println("<table border=\"2\" cellpadding=\"2\">");
    writer.println("<tr>");
    writer.println("<th align=\"left\" valign=\"top\">Version</th>");
    writer.println("<td colspan=\"2\">"+cert.getVersion()+"</td>");
    writer.println("</tr>");
    writer.println("<tr>");
    writer.println("<th align=\"left\" valign=\"top\">Serial Number </th>");
    writer.println("<td colspan=\"2\">0x"+cert.getSerialNumber().toString(16)+"</td>");
    writer.println("</tr>");
    writer.println("<tr>");
    writer.println("<th align=\"left\" valign=\"top\">Signature Algorithm</th>");
    writer.println("<td colspan=\"2\">"+cert.getSigAlgName()+"</td>");
    writer.println("</tr>");
    writer.println("<tr>");
    writer.println("<th align=\"left\" valign=\"top\">Subject</th>");
    writer.println("<td colspan=\"2\">");
    printDN(writer, cert.getSubjectDN());
    writer.println("</td>");
    writer.println("</tr>");
    writer.println("</tr>");
    writer.println("<tr>");
    writer.println("<th rowspan=\"2\" align=\"left\" valign=\"top\">Valid</th>");
    writer.println("<td>Not Before</td>");
    writer.println("<td>"+cert.getNotBefore()+"</td>");
    writer.println("</tr>");
    writer.println("<tr>");
    writer.println("<td>Not After</td>");
    writer.println("<td>"+cert.getNotAfter()+"</td>");
    writer.println("</tr>");
    writer.println("<th align=\"left\" valign=\"top\">Issuer</th>");
    writer.println("<td colspan=\"2\">");
    printDN(writer, cert.getIssuerDN());
    writer.println("</td>");
    writer.println("<tr>");

    PublicKey public_key = cert.getPublicKey();
    String algorithm = public_key.getAlgorithm().toUpperCase(Locale.US);

    if (algorithm.equals("RSA")) {
      writer.println("<tr><th rowspan=\"4\" align=\"left\" valign=\"top\">Public Key</th>");
      writer.println("<td>Algorithm</td>");
      writer.println("<td>"+algorithm+"</td>");
      writer.println("</tr>");

      RSAPublicKey rsaKey = (RSAPublicKey)public_key;
      BigInteger modulus = rsaKey.getModulus();

      writer.println("<tr><td>Key length</td><td>" + modulus.bitLength() + " bit</td></tr>");

      printKeyValue(writer, "Modulus", modulus);
      printKeyValue(writer, "Public Exponent", rsaKey.getPublicExponent());
    }
    else if (algorithm.equals("DSA")) {
      writer.println("<tr><th rowspan=\"6\" align=\"left\" valign=\"top\">Public Key</th>");
      writer.println("<td>Algorithm</td>");
      writer.println("<td>"+algorithm+"</td>");
      writer.println("</tr>");

      DSAPublicKey dsaKey = (DSAPublicKey)public_key;
      DSAParams params = dsaKey.getParams();

      writer.println("<tr><td>Key length</td><td>" + params.getP().bitLength() + " bit</td></tr>");

      printKeyValue(writer, "Public Key", dsaKey.getY());
      printKeyValue(writer, "G", params.getG());
      printKeyValue(writer, "Q", params.getQ());
      printKeyValue(writer, "P", params.getP());
    }
    else if (algorithm.equals("DH")) {
      writer.println("<tr><th rowspan=\"5\" align=\"left\" valign=\"top\">Public Key</th>");
      writer.println("<td>Algorithm</td>");
      writer.println("<td>"+algorithm+"</td>");
      writer.println("</tr>");

      DHPublicKey dhKey = (DHPublicKey)public_key;
      DHParameterSpec params = dhKey.getParams();

      writer.println("<tr><td>Key length</td><td>" + params.getP().bitLength() + " bit</td></tr>");

      printKeyValue(writer, "Public Key", dhKey.getY());
      printKeyValue(writer, "G", params.getG());
      printKeyValue(writer, "P", params.getP());
    }
    else if (algorithm.startsWith("EC")) {
      writer.println("<tr><th rowspan=\"3\" align=\"left\" valign=\"top\">Public Key</th>");
      writer.println("<td>Algorithm</td>");
      writer.println("<td>"+algorithm+"</td>");
      writer.println("</tr>");
      SecurityProvider securityProvider = SecurityProvider.getSecurityProvider();
      writer.println("<tr><td>Key length</td><td>" + securityProvider.getKeyLength(public_key) + " bit</td></tr>");
      String curveName = securityProvider.getCurveName(public_key);
      if (curveName != null) {
        writer.println("<tr><td>Curve</td><td>" + curveName + "</td></tr>");
      } 
    }
    else {
      writer.println("<tr><th rowspan=\"2\" align=\"left\" valign=\"top\">Public Key</th>");
      writer.println("<td>Algorithm</td>");
      writer.println("<td>"+algorithm+"</td>");
      writer.println("</tr>");

      writer.println("<tr>");
      writer.println("<td>Unknown key algorithm!</td>");
      writer.println("</tr>");
    }
    // end public key

    //extensions
    Enumeration e = cert.listExtensions();
    if (e != null) {
      for (int i=1; e.hasMoreElements(); i++) {
        V3Extension extension = (V3Extension)e.nextElement();
        writer.println("<tr>");
        writer.println("<th align=\"left\" valign=\"top\">Extension "+i+"</th>");
        writer.print("<td colspan=\"2\"><EM>");
        writer.print(extension.getName() + ":</EM><BR><PRE>");
        try {
          CharArrayWriter out = new CharArrayWriter();
          out.write(extension.toString());
          BufferedReader reader = new BufferedReader(new CharArrayReader(out.toCharArray()));
          while( true ) {
            String s = reader.readLine();
            if( s == null ) {
              break;
            }
            while( s.length() > 0 ) {
              int n = 60;
              if( n > s.length() ) {
                n = s.length();
                writer.println(s);
                break;
              }
              writer.println(s.substring(0, n));
              s = s.substring(n);
            }
          }
        } catch( IOException ex ) {
          // ignore
        }
        writer.println("</pre></td>");
        writer.println("</tr>");
      }
    }
    writer.println("</table>");
  }

  private static int getWeight(ObjectID objId) {
    if( objId.equals(ObjectID.commonName) ) {
      return 1;
    } else if( objId.equals(ObjectID.surName) ) {
      return 2;
    } else if( objId.equals(ObjectID.emailAddress) ) {
      return 3;
    } else if( objId.equals(ObjectID.organization) ) {
      return 4;
    } else if( objId.equals(ObjectID.organizationalUnit) ) {
      return 5;
    } else if( objId.equals(ObjectID.stateOrProvince) ) {
      return 7;
    } else if( objId.equals(ObjectID.country) ) {
      return 8;
    } else if( objId.equals(ObjectID.locality) ) {
      return 9;
    } else {
      return 6;
    }
  }

  private static void insertSorted(Vector v, AVA ava) {
    ObjectID next = ava.getType();
    int weight = getWeight(next);
    if( v.size() == 0 ) {
    }
    int n = v.size();
    for( int i=0; i<n; i++ ) {
      ObjectID cur = ((AVA)v.elementAt(i)).getType();
      int curWeight = getWeight(cur);
      if( weight < curWeight ) {
        v.insertElementAt(ava, i);
        return;
      }
    }
    v.addElement(ava);
  }

  public static void printDN(PrintWriter writer, Principal principal) {
    Vector v = new Vector();
    for (Enumeration e = ((Name)principal).elements(); e.hasMoreElements(); ) {
      RDN rdn = (RDN)e.nextElement();
      for( Enumeration e2 = rdn.elements(); e2.hasMoreElements(); ) {
        AVA ava = (AVA)e2.nextElement();
        insertSorted(v, ava);
      }
    }
    for( Enumeration e = v.elements(); e.hasMoreElements(); ) {
      AVA ava = (AVA)e.nextElement();
      ObjectID objID = ava.getType();
      Object value = ava.getValue();
      StringBuffer shortName = new StringBuffer(objID.getShortName());
      while( shortName.length() < 2 ) {
        shortName.append("&nbsp;");
      }
      writer.println("<em>" + shortName.toString() + "</em> = " + value + "<br>");
    }
  }

  public static void printKeyValue(PrintWriter writer, String name, BigInteger value) {
    writer.println("<tr>");
    writer.println("<td>"+name+"</td>");
    writer.print("<td><code>");
    String mod = value.toString(10).toUpperCase();
    int i=0;
    do {
      writer.print("&nbsp;");
      writer.print(mod.substring(i, Math.min(i+40, mod.length())));
      writer.println("<br>");
      i+=40;
    } while (i < mod.length());
    writer.println("</code></td></tr>");
  }

  public static void writeNameAndValues(PrintWriter writer, String title, Hashtable table) {
    writer.println("<H2>" + title + "</H2>");

    Vector[] nameAndValues = sortAlgorithms(table);
    int n = nameAndValues[0].size();
    writer.println("<TABLE BORDER CELLPADDING=\"3\">");
    writer.println("<TR><TH>Algorithm Name</TH><TH>Supported</TH>");
    for( int i=0; i<n; i++ ) {
      writer.println("<TR><TD>");
      writer.print(nameAndValues[0].elementAt(i));
      writer.println("</TD><TD>");
      boolean supported = ((Boolean)nameAndValues[1].elementAt(i)).booleanValue();
      if( supported ) {
        writer.print("yes");
      } else {
        writer.print("no");
      }
      writer.println("</TD>");
    }
    writer.println("</TABLE>");
  }

  public static void printCertificateChain(PrintWriter writer, String title, X509Certificate[] chain) {
    writer.println("<H2>" + title + "</H2>");

    if( (chain == null) || (chain.length == 0) ) {
      writer.println("(none)");
    } else {
      int n = chain.length;
      for( int i=0; i<n; i++ ) {
        writer.print("<H3>Certificate " + i + "</H3>");
        printCertificate(writer, chain[i]);
      }
    }
  }

  private static String toYesNo(boolean value) {
    return value ? "yes" : "no";
  }

  private static Vector[] sortAlgorithms(Hashtable table) {
    int n = table.size();
    Vector names = new Vector(n);
    Vector values = new Vector(n);
    for( Enumeration e = table.keys(); e.hasMoreElements(); ) {
      String name = (String)e.nextElement();
      Boolean value = (Boolean)table.get(name);
      int i=0;
      int k = names.size();
      while( i < k ) {
        String current = (String)names.elementAt(i);
        if( name.compareTo(current) < 0 ) {
          break;
        }
        i++;
      }
      names.insertElementAt(name, i);
      values.insertElementAt(value, i);
    }
    return new Vector[] { names, values };
  }

  public static String getCipherName(CipherSuite suite) {
    String cipher = suite.getCipherAlgorithm();
    int index = cipher.indexOf("/");
    if( index != -1 ) {
      return cipher.substring(0, index);
    } else {
      return cipher;
    }
  }

  public static void addCipherSuite(CipherSuite suite, Hashtable supportedKeyExchange, Hashtable supportedCiphers, boolean value) {
    Boolean b = value ? TRUE : FALSE;
    
    String keyExchange = suite.getKeyExchangeAlgorithm();
    if (!"TLS13".equals(keyExchange)) {
      if( (supportedKeyExchange.get(keyExchange) == null) || (value == true) ) {
        supportedKeyExchange.put(keyExchange, b);
      }
    }  

    String cipher = getCipherName(suite);
    if( (supportedCiphers.get(cipher) == null) || (value == true) ) {
      supportedCiphers.put(cipher, b);
    }
  }

  public static void printCipherSuiteList(PrintWriter writer, CipherSuiteList list) {
    if( list.size() == 0 ) {
      writer.println("(none)");
    } else {
      for( Enumeration e = list.elements(); e.hasMoreElements(); ) {
        writer.println(e.nextElement());
      }
    }
  }
  
  public static void printExtensionList(PrintWriter writer, ExtensionList list) {
    if( list == null ) {
      writer.println("<BLOCKQUOTE><PRE>");
      writer.println("(none)");
      writer.println("</BLOCKQUOTE></PRE>");
    } else {
      writer.println("<table border=\"2\" cellpadding=\"2\">");
      //extensions
      Enumeration e = list.listExtensions();
      for (int i=1; e.hasMoreElements(); i++) {
        Extension extension = (Extension)e.nextElement();
        writer.println("<tr>");
        writer.println("<th align=\"left\" valign=\"top\">Extension "+i+"</th>");
        writer.print("<td colspan=\"2\"><EM>");
        writer.print(extension.getName() + " (" + extension.getType() + "):</EM><BR><PRE>");
        try {
          CharArrayWriter out = new CharArrayWriter();
          out.write(extension.toString());
          BufferedReader reader = new BufferedReader(new CharArrayReader(out.toCharArray()));
          while( true ) {
            String s = reader.readLine();
            if( s == null ) {
              break;
            }
            while( s.length() > 0 ) {
              int n = 60;
              if( n > s.length() ) {
                n = s.length();
                writer.println(s);
                break;
              }
              writer.println(s.substring(0, n));
              s = s.substring(n);
            }
          }
        } catch( IOException ex ) {
          // ignore
        }
        writer.println("</pre></td>");
        writer.println("</tr>");
      }
    
      writer.println("</table>");
    }
  }
  
  
}
