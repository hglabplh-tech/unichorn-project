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
//$Header: /TSP/current/demo/src/demo/tsp/connections/http/TspHttpServerServlet.java 12    14.03.13 17:38 Dbratko $
//$Revision: 12 $
//

package harry.security.responder.resources;

import iaik.asn1.CodingException;
import iaik.security.provider.IAIK;
import iaik.tsp.PKIStatus;
import iaik.tsp.PKIStatusInfo;
import iaik.tsp.TSTInfo;
import iaik.tsp.TimeStampReq;
import iaik.tsp.TimeStampResp;
import iaik.tsp.TimeStampToken;
import iaik.tsp.TspSigningException;
import iaik.tsp.transport.http.TspHttpConstants;
import iaik.x509.X509Certificate;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Calendar;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.harry.security.util.httpclient.NTPServerUtil;
import org.pmw.tinylog.Logger;

/**
 * This demo class extends the <code>HttpServlet</code>.<br>
 * After receiving and verifying a <code>TimeStampReq</code> the servlet answers with a
 * <code>TimeStampResp</code> or a HTTP error.
 */
public class TspHttpServerServlet extends HttpServlet {


  /**
   * Used to generate an unique serial number
   */
  private static int serial_number_counter_ = 0;

  /**
   * Indicates whether the configuration is loaded or not
   */
  private boolean configLoaded_ = false;

  /**
   * The used configuration
   */
  private TspServerConfiguration config_;

  /**
   * Loads the configuration file and initializes the servlet.
   * @see javax.servlet.GenericServlet#init()
   */
  public void init() throws ServletException {
    if (!configLoaded_) {
      Logger.trace("Initializing Servlet");
      IAIK.addAsJDK14Provider();
      config_ = new TspServerConfiguration();
      try {
        config_.loadConfiguration(null);
      } catch (IOException e) {
        throw new ServletException(e);
      } catch (TspServerConfigurationException e) {
        throw new ServletException(e);
      }
      configLoaded_ = true;
    }
  }

  /**
   * This method receives a {@link TimeStampReq} and answers with a {@link TimeStampResp}.<br>
   * For more details please refer to <a href="http://www.ietf.org/rfc/rfc3161.txt">RFC 3161</a>. 
   * @see HttpServlet#doPost(HttpServletRequest, HttpServletResponse)
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException,
      IOException {
    UnichornResponder.initReq();
    OutputStream toClient = response.getOutputStream();
    TimeStampReq tspRequest = null;
    String client_id_string_ = request.getRemoteAddr();
    byte[] tspReq = null;

    try {
      Logger.trace("[" + client_id_string_ + "]" + " Connected");

      String contentType = request.getContentType();
      if (contentType == null || (!contentType.equalsIgnoreCase(TspHttpConstants.CONTENT_TYPE_REQUEST))) {
        Logger.trace("[" + client_id_string_ + "]" + " Illegal content type: " + contentType);
        response.sendError(400);
        return;
      }

      //get input & output streams
      InputStream fromClient = request.getInputStream();


      //read request
      byte[] buff = new byte[1024];
      ByteArrayOutputStream tmp = new ByteArrayOutputStream();
      int read;
      while ((read = fromClient.read(buff)) != -1) {
        tmp.write(buff, 0, read);
      }
      tspReq = tmp.toByteArray();

    } catch (Exception ex) {
      Logger.trace("TSP pre-processing failed with : -> "
              + ex.getMessage()
              + " class is " + ex.getClass().getCanonicalName());
      response.sendError(400);

    }

    try {
      tspRequest = new TimeStampReq(tspReq);
    } catch (CodingException e) {
      Logger.error("[" + client_id_string_ + "]" + " Internal Server error: " + e.getMessage());
      response.sendError(400);
      return;
    }

    Logger.trace("[" + client_id_string_ + "]" + " Valid TimeStampRequest received");

    TimeStampResp resp = null;

    //create TSTInfo
    TSTInfo tstInfo = new TSTInfo();
    Calendar time = NTPServerUtil.getNTPTime();
    Date atomicTime = new Date(time.getTimeInMillis());
    tstInfo.setGenTime(atomicTime);
    tstInfo.setMessageImprint(tspRequest.getMessageImprint());
    if (config_.setAccuracy()) {
      tstInfo.setAccuracy(config_.getAccuracy());
    }
    if (tspRequest.getNonce() != null) {
      tstInfo.setNonce(tspRequest.getNonce());
    }
    tstInfo.setSerialNumber(generateSerialNumber());
    tstInfo.setTSAPolicyID(config_.getObjectID());

    //create TimeStampToken
    TimeStampToken token = new TimeStampToken(tstInfo);
    X509Certificate[] tsaCerts = config_.getTSACertChain(); 
    if (tspRequest.getCertReq()) {
      token.setCertificates(tsaCerts);
    }
    token.setSigningCertificate(tsaCerts[0]);

    token.setHashAlgorithm(config_.getHashAlgorithm());
    token.addSha1ESSCertID(config_.getAddSha1CertID());
    token.setPrivateKey(config_.getPrivateKey());

    try {
      token.signTimeStampToken();
    } catch (TspSigningException e2) {
      Logger.error("[" + client_id_string_ + "]" + " Internal Server error: " + e2.getMessage());
      response.sendError(500);
      return;
    }

    resp = new TimeStampResp();
    resp.setTimeStampToken(token);

    PKIStatus status = new PKIStatus(PKIStatus.GRANTED);
    PKIStatusInfo info = new PKIStatusInfo(status);

    resp.setPKIStatusInfo(info);

    byte[] time_stamp = resp.getEncoded();

    Logger.trace("[" + client_id_string_ + "]" + " Sending TimeStampResponse");
    response.setContentLength(time_stamp.length);
    response.setContentType(TspHttpConstants.CONTENT_TYPE_REPLY);
    toClient.write(time_stamp);
    Logger.trace("[" + client_id_string_ + "]" + " TimeStampResponse sent");
  }

  /**
   * Will be forwarded to {@link #doPost(HttpServletRequest, HttpServletResponse)}.
   * @see HttpServlet#doGet(HttpServletRequest, HttpServletResponse)
   */
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException,
      IOException {
    doPost(request, response);
  }

  /**
   * Creates an unique serial number.
   * @return An unique serial number.
   */
  protected synchronized BigInteger generateSerialNumber() {
    return new BigInteger(String.valueOf(new Date().getTime()) + serial_number_counter_++);
  }
}