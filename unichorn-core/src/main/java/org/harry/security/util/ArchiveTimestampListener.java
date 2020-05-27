package org.harry.security.util;

import iaik.asn1.CodingException;
import iaik.asn1.DerCoder;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.AttributeValue;
import iaik.cms.*;
import iaik.pdf.asn1objects.AbstractAtsHashIndex;
import iaik.pdf.asn1objects.ArchiveTimeStampv3;
import iaik.pdf.asn1objects.AtsHashIndex;
import iaik.pdf.asn1objects.AtsHashIndexv3;
import iaik.pdf.parameters.CadesLTAParameters;
import iaik.tsp.TimeStampReq;
import iaik.tsp.TimeStampResp;
import iaik.tsp.TspException;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;

public class ArchiveTimestampListener extends SDSEncodeListener {

    private final boolean useHashIdxV3;
    private final String tspAlg;
    private final CertificateIdentifier certId;
    private final String passwd;
    private final String userName;
    private final String tsaURL;



    /**
     * The TimeStamp request (to be created and sent).
     */
    private TimeStampReq request_;

    /**
     * The TimeStamp response (received from the TSA).
     */
    private TimeStampResp response_;

    /**
     * The TSA policy ID, if requested.
     */
    private ObjectID tsaPolicyID_;

    /**
     * Finish SignedData creation and do not include TimeStampToken attribute
     * if TSA response is invalid?
     */
    private boolean stopOnTSPProcessingError_;

    /**
     * Exception indicating an error during TSP processing.
     */
    private TspException tspFailure_;

    /**
     * Writer to which debug information may be written.
     */
    private PrintWriter debugWriter_;
    private OutputStream temp;


    public ArchiveTimestampListener(CadesLTAParameters var1, CertificateIdentifier var2) {
        this.tsaURL = var1.getTsaUrl();
        this.userName = var1.getTsaUsername();
        this.passwd = var1.getTsaPw();
        this.tspAlg = var1.getTimestampDigestAlgorithm();
        this.useHashIdxV3 = var1.getUseAtsHashIndexv3();
        this.certId = var2;
        temp = this.getOutputStream();
        this.setOutputStream(null);
    }

    @Override
    protected void afterComputeSignature(SignedDataStream signedDataStream) throws CMSException {
        SignerInfo signerInfo = signedDataStream.getSignerInfos()[0];
        CertificateSet certSet = signedDataStream.getCertificateSet();
        CertificateChoices[] choices = certSet.getCertificateChoices();
        AlgorithmID tspAlgID = AlgorithmID.getAlgorithmID(this.tspAlg);
        Attribute[] unsignedAttrs = signerInfo.getUnsignedAttributes();

        Object atsHashIndex = null;
        if (this.useHashIdxV3) {

            try {
                atsHashIndex = new AtsHashIndexv3(tspAlgID, choices, signedDataStream.getRevocationInfoChoices().getRevocationInfoChoices(), unsignedAttrs);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (CodingException e) {
                e.printStackTrace();
            }

        } else {

            try {
                atsHashIndex = new AtsHashIndex(tspAlgID, choices, signedDataStream.getRevocationInfoChoices().getRevocationInfoChoices(), unsignedAttrs);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (CodingException e) {
                e.printStackTrace();
            }

        }
        try {
            byte[] imprint = CadesLTAParameters.calculateArchiveTimestampImprint(signedDataStream, signerInfo, tspAlgID, DerCoder.encode(((AbstractAtsHashIndex)atsHashIndex).toASN1Object()));
            if (response_ == null) {
                debug("Create time stamp request.");
                request_ = TSPUtils.createRequest(signerInfo, null);
                debug("Send time stamp request to " + tsaURL);
                response_ = TSPUtils.sendRequest(request_, tsaURL);
                // validate the response
                debug("Validate response.");
                TSPUtils.validateResponse(response_, request_);
                debug("Response ok.");
                response_.getTimeStampToken().getSignerInfo().addUnsignedAttribute(new Attribute((AttributeValue)atsHashIndex));
                ArchiveTimeStampv3 archTSP = new ArchiveTimeStampv3(response_.getTimeStampToken().toASN1Object());
                signerInfo.addUnsignedAttribute(new Attribute(archTSP));
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CodingException | TspException e) {
            e.printStackTrace();
        }
        finally {
            this.setOutputStream(temp);
        }
    }

    @Override
    protected void beforeComputeSignature(SignedDataStream signedDataStream) throws CMSException {

    }

    /**
     * Prints the given debug message.
     *
     * @param msg the debug message to be printed.
     */
    private void debug(String msg) {
        if (debugWriter_ != null) {
            debugWriter_.println(msg);
        }
    }
}
