package org.harry.security.util;

import com.itextpdf.text.DocumentException;
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
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;
import org.harry.security.util.algoritms.DigestAlg;
import org.harry.security.util.bean.SigningBean;
import org.pmw.tinylog.Logger;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
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
    /**
     *
     * Sign the given file using the previously set key.
     *
     * @throws IOException
     *           if a file can't be read or written
     * @throws PdfSignatureException
     *           if errors during signing occur
     */
    public void signPdf()
            throws IOException, PdfSignatureException {



        // create signed pdf using specified name
        pdfSignatureInstance.sign();
    }

    /**
     * Prepare the signature parameters and initialize signature instance.
     *
     * @param bean
     *          the data for preparing
     * @param params
     *          the bes parameters
     * @throws IOException
     *           if document can't be read or written
     * @throws PdfSignatureException
     *           if parameters are invalid or certificates can't be parsed
     */
    public void prepareSigning(SigningBean bean, PadesBESParameters params)
            throws IOException, PdfSignatureException {


        FileOutputStream stream = new FileOutputStream(bean.getOutputPath());
        pdfSignatureInstance.initSign(bean.getDataIN(), null, stream, privKey,
                certChain, params);

        InputStream image = SignPDFUtil.class.getResourceAsStream("/graphic/cert.png");
        PDVisibleSignDesigner visibleSig = new PDVisibleSignDesigner(image);
        visibleSig.coordinates(0,-100).zoom(-50)
                .adjustForRotation()
                .signatureFieldName("ApplicantSignature");
        PDVisibleSigProperties signatureProperties = new PDVisibleSigProperties();
        signatureProperties.signerName(params.getSignatureContactInfo())
                .signerLocation(params.getSignatureLocation())
                .signatureReason(params.getSignatureReason()).preferredSize(40).page(1)
                .visualSignEnabled(true).setPdVisibleSignature(visibleSig)
                .buildSignature();

    }

    public PadesBESParameters createParameters(SigningBean bean) throws Exception {
        TSAClientIAIK client = new
                TSAClientIAIK(bean.getTspURL());
        int estimate = client.getTokenSizeEstimate();
        estimate = estimate * 2;
        client = new
                TSAClientIAIK(bean.getTspURL(), null, null, estimate,
                DigestAlg.SHA256.getAlgId().getImplementationName());
        PadesBESParameters params = new PadesBESParameters();
        params.getEstimatedLength();

        params.setSignatureReason("test");
        params.setSignatureLocation("Stuttgart");
        params.setSignatureContactInfo("Ronny");
        // set timestamp authority to add timestamp as unsigned attribute in
        // signature
        System.out.println("configuring signature engine to include a timestamp.");
        if (bean.getTspURL() != null) {
            /**
             * TODO: if we set the next two lines we get the following runtime exception:
             * java.io.IOException: Signature too large for allocated space, unknown attributes may be used
             *
             * 	at iaik.pdf.itext.PdfSignatureInstanceItext.a(Unknown Source)
             * 	at iaik.pdf.itext.PdfSignatureInstanceItext.sign(Unknown Source)
             * 	at org.harry.security.util.SignPDFUtil.signPdf(SignPDFUtil.java:52)
             * 	at org.harry.security.util.SignPDFUtilTest.signPDFSSimple(SignPDFUtilTest.java:30)
             * 	at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
             * 	at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
             * 	at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
             * 	at java.lang.reflect.Method.invoke(Method.java:498)
             * 	at org.junit.runners.model.FrameworkMethod$1.runReflectiveCall(FrameworkMethod.java:59)
             * 	at org.junit.internal.runners.model.ReflectiveCallable.run(ReflectiveCallable.java:12)
             * 	at org.junit.runners.model.FrameworkMethod.invokeExplosively(FrameworkMethod.java:56)
             * 	at org.junit.internal.runners.statements.InvokeMethod.evaluate(InvokeMethod.java:17)
             * 	at org.junit.runners.ParentRunner$3.evaluate(ParentRunner.java:306)
             * 	at org.junit.runners.BlockJUnit4ClassRunner$1.evaluate(BlockJUnit4ClassRunner.java:100)
             * 	at org.junit.runners.ParentRunner.runLeaf(ParentRunner.java:366)
             * 	at org.junit.runners.BlockJUnit4ClassRunner.runChild(BlockJUnit4ClassRunner.java:103)
             * 	at org.junit.runners.BlockJUnit4ClassRunner.runChild(BlockJUnit4ClassRunner.java:63)
             * 	at org.junit.runners.ParentRunner$4.run(ParentRunner.java:331)
             * 	at org.junit.runners.ParentRunner$1.schedule(ParentRunner.java:79)
             * 	at org.junit.runners.ParentRunner.runChildren(ParentRunner.java:329)
             * 	at org.junit.runners.ParentRunner.access$100(ParentRunner.java:66)
             * 	at org.junit.runners.ParentRunner$2.evaluate(ParentRunner.java:293)
             * 	at org.junit.runners.ParentRunner$3.evaluate(ParentRunner.java:306)
             * 	at org.junit.runners.ParentRunner.run(ParentRunner.java:413)
             * 	at org.junit.runner.JUnitCore.run(JUnitCore.java:137)
             * 	at com.intellij.junit4.JUnit4IdeaTestRunner.startRunnerWithArgs(JUnit4IdeaTestRunner.java:68)
             * 	at com.intellij.rt.junit.IdeaTestRunner$Repeater.startRunnerWithArgs(IdeaTestRunner.java:33)
             * 	at com.intellij.rt.junit.JUnitStarter.prepareStreamsAndStart(JUnitStarter.java:230)
             * 	at com.intellij.rt.junit.JUnitStarter.main(JUnitStarter.java:58)
             * 	This exception is documented as a internal LIB error so we have to research later on.
             */
           params.setSignatureTimestampProperties(bean.getTspURL(), null, null);
            //params.setContentTimestampProperties(bean.getTspURL(), null, null);
        }
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
                "IAIK", MakeSignature.CryptoStandard.CMS,
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
            appearance.setContact(contact);
            appearance.setReason(reason);
            appearance.setLocation(location);
            appearance.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, "sig");
            // Creating the signature
            ExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm,
                    signatureProvider);
            ExternalDigest digest = new ProviderDigest(mdProvider);
            MakeSignature.signDetached(appearance, digest, pks, chain,null, ocspClient,
                    tsaClient, estimatedSize, subfilter);
        }
    }

    public static void printUsage() {
        System.out.println(
                "Usage: SignWithExternalProvider <PKCS#12 file> <password for PKCS#12 file>");
        System.out.println(" e.g.: SignWithExternalProvider mykeys.p12 password");
    }

}



