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
//$Header: /TSP/current/demo/src/demo/tsp/config/TspServerConfigurationException.java 5     10.05.10 12:35 Dbratko $
//$Revision: 5 $
//

package harry.security.responder.resources;

/**
 * This exception will be used if an error occurs during configuration loading.
 */
public class TspServerConfigurationException extends Exception {

  /**
   * Constructs an <code>Exception</code> with no specified detail message.
   */
  public TspServerConfigurationException() {
    super();
  }

  /**
   * Constructs an <code>Exception</code> with the specified detail message.
   */
  public TspServerConfigurationException(String msg) {
    super(msg);
  }

}