package harry.security.responder.resources;

import iaik.asn1.CodingException;
import iaik.asn1.structures.AlgorithmID;
import iaik.utils.ASN1InputStream;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.*;
import iaik.x509.ocsp.extensions.CrlID;
import iaik.x509.ocsp.utils.ResponseGenerator;
import org.harry.security.util.SigningUtil;
import org.harry.security.util.certandkey.CertWriterReader;


import javax.servlet.*;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;

import java.io.*;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;

import static org.harry.security.util.certandkey.CertWriterReader.loadSecrets;


public class UnichornResponder extends HttpServlet {

    /**
     * Use an OCSP ResponseGenerator for request parsing / response generation.
     */
    private ResponseGenerator responseGenerator;
    /**
     * Algorithm to be used for signing the response.
	 */
    private AlgorithmID signatureAlgorithm;

    @Override
    public void service(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws ServletException, IOException {
        String output = "Jersey say : ";
        System.out.println("Hallo here I am");
        try {
            HttpServletResponse response = (HttpServletResponse)servletResponse;
            ServletInputStream stream = servletRequest.getInputStream();
            OCSPRequest ocspRequest = new OCSPRequest(stream);
            ocspRequest.getCertifcates();
            Request[] requests = ocspRequest.getRequestList();
            OCSPResponse ocspResp = generateResponse(ocspRequest);
            ocspResp.writeTo(servletResponse.getOutputStream());
            response.setStatus(200);
        } catch (Exception ex) {
            servletResponse.setStatus(400);
        }



    }

    public OCSPResponse generateResponse(OCSPRequest ocspRequest) throws OCSPException, SignatureException, IOException, CertificateException, CodingException {
        CertWriterReader.KeyStoreBean bean = loadSecrets(null, "JKS",
                "geheim", "RSA_MASTER");
        X509Certificate [] certs = new X509Certificate[1];
        certs[0] = bean.getSelectedCert();
        responseGenerator = new ResponseGenerator(bean.getSelectedKey(), certs);

        signatureAlgorithm = AlgorithmID.sha1WithRSAEncryption;
        PrivateKey responderKey = responseGenerator.getResponderKey();

        if (!(responderKey instanceof java.security.interfaces.RSAPrivateKey)) {
            if (responderKey instanceof java.security.interfaces.DSAPrivateKey) {
                signatureAlgorithm = AlgorithmID.dsa;
            } else {
                System.out.println("Error in initialization. Unknown key algorithm: "
                        + responderKey.getAlgorithm());
                System.exit(-1);
            }
        }
        responseGenerator.createOCSPResponse(new ByteArrayInputStream(ocspRequest.getEncoded()),
                null, signatureAlgorithm, null);
        // read crl

        X509CRL crl = readCrl(UnichornResponder.class.getResourceAsStream("/unichorn.crl"));
        System.out.println("Create response entries for crl...");
        X509Certificate crlIssuer = new X509Certificate(UnichornResponder.class
                .getResourceAsStream("/DeutscheTelekomAGIssuingCA01.crt"));
        responseGenerator.addResponseEntries(crl, crlIssuer, ReqCert.certID);
        System.out.println("Generator created:");
        System.out.println(responseGenerator);

        ByteArrayOutputStream os = null;
        try {
            os = new ByteArrayOutputStream();
            responseGenerator.writeTo(os);
            OCSPResponse response = new OCSPResponse(new ByteArrayInputStream(os.toByteArray()));
            return response;
        } catch (Exception ex) {
            throw new IllegalStateException("response was not generated ", ex);
        } finally {
            if (os != null) {
                try {
                    os.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        }
    }

    /**
     * Reads a X.509 crl from the given file.
     *
     * @param is
     *          the name of the crl file
     * @return the crl
     */
    private static X509CRL readCrl(InputStream is) {

        X509CRL crl = null;
        try {
            crl = new X509CRL(new ASN1InputStream(is));
        } catch (Exception ex) {
            ex.printStackTrace();
            System.exit(-1);
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        }
        return crl;
    }




}
