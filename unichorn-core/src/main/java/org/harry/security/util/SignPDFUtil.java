package org.harry.security.util;




import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Jpeg;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.*;
import iaik.pdf.cmscades.CadesSignature;
import iaik.pdf.cmscades.CmsCadesException;
import iaik.pdf.cmscades.OcspResponseUtil;
import iaik.pdf.itext.OcspClientIAIK;
import iaik.pdf.itext.TSAClientIAIK;
import iaik.pdf.parameters.PadesBESParameters;
import iaik.pdf.parameters.PadesLTVParameters;
import iaik.pdf.pdfbox.PdfSignatureInstancePdfbox;
import iaik.pdf.signature.PdfSignatureEngine;
import iaik.pdf.signature.PdfSignatureException;
import iaik.pdf.signature.PdfSignatureInstance;
import iaik.tsp.transport.http.TspHttpClient;
import iaik.x509.X509Certificate;
import org.harry.security.util.algoritms.DigestAlg;
import org.harry.security.util.bean.SigningBean;
import org.pmw.tinylog.Logger;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

public class SignPDFUtil {



    private PrivateKey privKey;
    private Certificate[] certChain;
    private PdfSignatureInstance pdfSignatureInstance;

    public SignPDFUtil(PrivateKey privKey, Certificate[] chain) {
        pdfSignatureInstance = PdfSignatureEngine.getInstance();
        this.privKey = privKey;
        certChain = chain;
        // you can add the ECCelerate provider, if you use EC keys
        // Security.addProvider(new ECCelerate());
    }



    public PadesBESParameters createParameters(SigningBean bean) throws Exception {
        PadesBESParameters params = new PadesBESParameters();
        if (bean.getDigestAlgorithm() != null) {
            params.setDigestAlgorithm(bean.getDigestAlgorithm().getAlgId().getJcaStandardName());
        }
        if (bean.getSignatureAlgorithm() != null) {
            params.setDigestAlgorithm(bean.getSignatureAlgorithm().getAlgId().getJcaStandardName());
        }
        if (bean.getTspURL() != null) {
            params.setContentTimestampProperties(bean.getTspURL(), null, null);
            params.setSignatureTimestampProperties(bean.getTspURL(), null, null);
        }
        params.setSignatureContactInfo("Harald Glab-Plhak");
        params.setSignatureLocation("Gäufelden");
        params.setSignatureReason("Just for fun");
        return params;
    }

    /**
     * Sign PDF document with a key from a pkcs12-keystore using the given provider.
     *
     * @param bean
     *          data for signing
     * @throws Exception
     *           in case of any exceptions
     */
    public void signPDF(SigningBean bean, PadesBESParameters params)
            throws Exception {

        PrivateKey pk = privKey;
        Certificate[] chain = certChain;
        String providerName = "IAIK";




        // include OCSP response
        OcspClient ocspClient = new OcspClientIAIK();


        // extract URL to timestamp server from certificate
        TSAClient tsaClient = null;
        int estimation = 0;
        // or use preferred timestamp server
        if (tsaClient == null) {
            String tsaUrl = bean.getTspURL();
            tsaClient = new TSAClientIAIK(tsaUrl);
            estimation = tsaClient.getTokenSizeEstimate() * 10;
        }

        // include CRLs in signature - let iText extract the CRLs
       // List<CrlClient> crlList = new ArrayList<CrlClient>();
        //crlList.add(new CrlClientOnline(chain));

        // sign <pdfToSign>, save signed PDF to <signedPdf>
        SignWithProvider app = new SignWithProvider();
        app.sign(bean.getDataIN(), bean.getOutputPath(), chain, pk, DigestAlgorithms.SHA256, providerName,
                "IAIK", MakeSignature.CryptoStandard.CADES,
                params.getSignatureReason(),
                params.getSignatureLocation(),
                params.getSignatureContactInfo(),
                ocspClient, tsaClient,
                estimation);


    }


    /**
     * helper class carrying out actual signature process
     */
    private static class SignWithProvider {

        /**
         * common signature method
         *
         * @param src
         *          path to PDF document that shall be signed
         * @param dest
         *          filename for the new signed PDF document
         * @param chain
         *          certificate chain
         * @param pk
         *          private key used for signing
         * @param digestAlgorithm
         *          used digest algorithm
         * @param signatureProvider
         *          JCE provider to be used for signature calculation
         * @param mdProvider
         *          JCE provider to be used for message digest calculation
         * @param subfilter
         *          used subfilter (cms or cades)
         * @param reason
         *          reason for signing
         * @param location
         *          location of signing

         * @param ocspClient
         *          OcspClient to be used to receive OCSP response
         * @param tsaClient
         *          TSAClient to create timestamp
         * @param estimatedSize
         *          estimated size of signature
         * @throws Exception
         *           in case of any problems
         */
        public void sign(InputStream src, String dest, Certificate[] chain, PrivateKey pk,
                         String digestAlgorithm, String signatureProvider, String mdProvider,
                         MakeSignature.CryptoStandard subfilter, String reason, String location,
                         String contact,
                         OcspClient ocspClient, TSAClient tsaClient,
                         int estimatedSize)
                throws GeneralSecurityException, IOException, DocumentException {

            // Creating the reader and the stamper
            PdfReader reader = new PdfReader(src);
            FileOutputStream os = new FileOutputStream(dest);
            PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
            // Creating the appearance
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            URL imageURL = SignPDFUtil.class.getResource("/graphic/cert.jpg");
            Jpeg image = new Jpeg(imageURL);
            appearance.setImage(image);
            appearance.setContact(contact);
            appearance.setReason(reason);
            appearance.setLocation(location);
            appearance.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, "sig");
            // Creating the signature
            ExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm,
                    signatureProvider);
            ExternalDigest digest = new ProviderDigest(mdProvider);





            MakeSignature.signDetached(appearance, digest, pks, chain, null, ocspClient,
                    tsaClient, estimatedSize, subfilter);

        }
    }


}



