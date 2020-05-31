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

import static org.harry.security.CommonConst.OCSP_URL;
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
 * @author Harald Glab-Plhak
 */
public class GenerateKeyStore  {


  /**
   * Generates the certificates.
   */
  public static void generateCertificates() throws IOException {
  // 'TODO: next to look at
    ConfigReader.MainProperties properties = ConfigReader.loadStore();
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
  

  


}