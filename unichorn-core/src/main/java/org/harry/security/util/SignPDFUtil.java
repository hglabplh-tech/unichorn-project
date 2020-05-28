package org.harry.security.util;




import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Jpeg;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.security.*;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.ProviderDigest;
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

import javax.activation.DataSource;
import java.io.*;
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
    public DataSource signPDF(SigningBean bean, PadesBESParameters params)
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
        DataSource ds = app.sign(bean.getDataIN(),  chain, pk, DigestAlgorithms.SHA256, providerName,
                "IAIK", MakeSignature.CryptoStandard.CADES,
                params.getSignatureReason(),
                params.getSignatureLocation(),
                params.getSignatureContactInfo(),
                ocspClient, tsaClient,
                estimation);

        return ds;

    }

    /**
     * Sign PDF document with a key from a pkcs12-keystore using the given provider.
     *
     * @param bean
     *          data for signing
     * @throws Exception
     *           in case of any exceptions
     */
    public DataSource certifyPDF(SigningBean bean, PadesBESParameters params)
            throws Exception {

        PrivateKey pk = privKey;
        Certificate[] chain = certChain;
        String providerName = "IAIK";





        // include CRLs in signature - let iText extract the CRLs
        // List<CrlClient> crlList = new ArrayList<CrlClient>();
        //crlList.add(new CrlClientOnline(chain));

        // sign <pdfToSign>, save signed PDF to <signedPdf>
        SignWithProvider app = new SignWithProvider();
        return app.certify(bean.getDataIN(), chain, pk,
                DigestAlgorithms.SHA256, providerName, PdfSigner.CryptoStandard.CMS,
                "Test", "Ghent", null, null, null, 0);

    }

    public DataSource timeStampPDF(SigningBean bean, PadesBESParameters params) throws Exception {
        // sign <pdfToSign>, save signed PDF to <signedPdf>
        SignWithProvider app = new SignWithProvider();
        // extract URL to timestamp server from certificate
        TSAClient tsaClient = null;
        int estimation = 0;
        // or use preferred timestamp server
        if (tsaClient == null) {
            String tsaUrl = bean.getTspURL();
            tsaClient = new TSAClientIAIK(tsaUrl);
            int estimate = tsaClient.getTokenSizeEstimate();
            estimate *= 3;
            tsaClient = new TSAClientIAIK(tsaUrl, null,null, estimate, DigestAlgorithms.SHA256);
        }
        return app.addDocumentTSP(bean.getDataIN(), params, tsaClient);
    }

    /**
     * helper class carrying out actual signature process
     */
    private static class SignWithProvider {

        /**
         * common signature method
         *
         * @param src               path to PDF document that shall be signed
         * @param chain             certificate chain
         * @param pk                private key used for signing
         * @param digestAlgorithm   used digest algorithm
         * @param signatureProvider JCE provider to be used for signature calculation
         * @param mdProvider        JCE provider to be used for message digest calculation
         * @param subfilter         used subfilter (cms or cades)
         * @param reason            reason for signing
         * @param location          location of signing
         * @param ocspClient        OcspClient to be used to receive OCSP response
         * @param tsaClient         TSAClient to create timestamp
         * @param estimatedSize     estimated size of signature
         * @throws Exception in case of any problems
         */
        public DataSource sign(InputStream src, Certificate[] chain, PrivateKey pk,
                               String digestAlgorithm, String signatureProvider, String mdProvider,
                               MakeSignature.CryptoStandard subfilter, String reason, String location,
                               String contact,
                               OcspClient ocspClient, TSAClient tsaClient,
                               int estimatedSize)
                throws GeneralSecurityException, IOException, DocumentException {

            // Creating the reader and the stamper
            PdfReader reader = new PdfReader(src);
            ByteArrayOutputStream os = new ByteArrayOutputStream();
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
            ByteArrayInputStream input = new ByteArrayInputStream(os.toByteArray());
            SigningUtil.InputStreamDataSource ds = new SigningUtil.InputStreamDataSource(input);
            return ds;

        }

        /**
         * common signature method
         *
         * @param src               path to PDF document that shall be signed
         * @param chain             certificate chain
         * @param pk                private key used for signing
         * @param digestAlgorithm   used digest algorithm
         * @param subfilter         used subfilter (cms or cades)
         * @param reason            reason for signing
         * @param location          location of signing
         * @param ocspClient        OcspClient to be used to receive OCSP response
         * @param tsaClient         TSAClient to create timestamp
         * @param estimatedSize     estimated size of signature
         * @throws Exception in case of any problems
         */
        public DataSource certify(InputStream src, Certificate[] chain, PrivateKey pk,
                         String digestAlgorithm, String provider, PdfSigner.CryptoStandard subfilter,
                         String reason, String location, Collection<ICrlClient> crlList,
                         IOcspClient ocspClient, ITSAClient tsaClient, int estimatedSize)
                throws GeneralSecurityException, IOException {
            com.itextpdf.kernel.pdf.PdfReader reader = new com.itextpdf.kernel.pdf.PdfReader(src);
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            PdfSigner signer = new PdfSigner(reader, os, true);
            signer.setCertificationLevel(PdfSigner.CERTIFIED_FORM_FILLING);

            // Create the signature appearance
            com.itextpdf.kernel.geom.Rectangle rect = new com.itextpdf.kernel.geom.Rectangle(36, 648, 200, 100);
            com.itextpdf.signatures.PdfSignatureAppearance appearance = signer.getSignatureAppearance();
            appearance
                    .setReason(reason)
                    .setLocation(location)

                    // Specify if the appearance before field is signed will be used
                    // as a background for the signed field. The "false" value is the default value.
                    .setReuseAppearance(false)
                    .setPageRect(rect)
                    .setPageNumber(1);


            IExternalSignature pks = new com.itextpdf.signatures.PrivateKeySignature(pk, digestAlgorithm, provider);
            IExternalDigest digest = new BouncyCastleDigest();

            // Sign the document using the detached mode, CMS or CAdES equivalent.
            signer.signDetached(digest, pks, chain, crlList, ocspClient, tsaClient, estimatedSize, subfilter);
            ByteArrayInputStream input = new ByteArrayInputStream(os.toByteArray());
            SigningUtil.InputStreamDataSource ds = new SigningUtil.InputStreamDataSource(input);
            return ds;
        }

        public DataSource addDocumentTSP(InputStream src,
                                   PadesBESParameters params,
                                   TSAClient tsaClient)
                throws IOException, DocumentException, GeneralSecurityException {
            // Creating the reader and the stamper
            PdfReader reader = new PdfReader(src);
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);
            AcroFields fields = stamper.getAcroFields();

            List<String> names = fields.getSignatureNames();
            String sigName = names.get(names.size() - 1);


            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            URL imageURL = SignPDFUtil.class.getResource("/graphic/cert.jpg");
            Jpeg image = new Jpeg(imageURL);
            appearance.setImage(image);
            appearance.setContact(params.getSignatureContactInfo());
            appearance.setReason(params.getSignatureReason());
            appearance.setLocation(params.getSignatureLocation());
            LtvTimestamp.timestamp(appearance, tsaClient, "timestamp-all");
            ByteArrayInputStream input = new ByteArrayInputStream(os.toByteArray());
            SigningUtil.InputStreamDataSource ds = new SigningUtil.InputStreamDataSource(input);
            return ds;
        }
    }


}



