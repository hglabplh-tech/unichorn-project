package org.harry.security.util.bean;

import iaik.cms.SignedData;
import org.harry.security.CMSSigner;
import org.harry.security.util.SigningUtil;
import org.harry.security.util.algoritms.CryptoAlg;
import org.harry.security.util.algoritms.DigestAlg;
import org.harry.security.util.algoritms.SignatureAlg;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.trustlist.TrustListWalkerAndGetter;

import javax.activation.DataSource;
import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class SigningBean {


    private CMSSigner.Commands action;

    private String alias;

    private String keyStoreType = "JKS";

    private boolean checkPathOcsp = false;

    private String decryptPWD;

    private CertWriterReader.KeyStoreBean keyStoreBean;

    private InputStream dataIN;

    private InputStream certIN;

    private DataSource outputDS;

    private String outputPath;

    private Mode signingMode;

    private SigningType signatureType;

    private DigestAlg digestAlgorithm = null;

    private SignatureAlg signatureAlgorithm= null;

    private CryptoAlg cryptoAlgorithm = null;
    private String signedWithAlias;

    private DataSource dataSource = null;

    private String tspURL;
    private File dataINPath;

    List<TrustListWalkerAndGetter> walker = new ArrayList<>();

    public enum Mode {
        EXPLICIT(SignedData.EXPLICIT),
        IMPLICIT(SignedData.IMPLICIT);
        private Integer mode = SignedData.EXPLICIT;

        Mode(Integer mode) {
            this.mode = mode;
        }

        public Integer getMode() {
            return mode;
        }
    }

    public enum SigningType {
        CMS,
        CAdES;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public SigningBean setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
        return this;
    }

    public boolean isCheckPathOcsp() {
        return checkPathOcsp;
    }

    public SigningBean setCheckPathOcsp(boolean checkPathOcsp) {
        this.checkPathOcsp = checkPathOcsp;
        return this;
    }

    public CMSSigner.Commands getAction() {
        return action;
    }

    public SigningBean setAction(CMSSigner.Commands action) {
        this.action = action;
        return this;
    }

    public String getAlias() {
        return alias;
    }

    public String getSignedWithAlias() {
        return signedWithAlias;
    }

    public SigningBean setSignedWithAlias(String signedWithAlias) {
        this.signedWithAlias = signedWithAlias;
        return this;
    }

    public SigningBean setAlias(String alias) {
        this.alias = alias;
        return this;
    }

    public String getDecryptPWD() {
        return decryptPWD;
    }

    public SigningBean setDecryptPWD(String decryptPWD) {
        this.decryptPWD = decryptPWD;
        return this;
    }

    public CertWriterReader.KeyStoreBean getKeyStoreBean() {
        return keyStoreBean;
    }

    public SigningBean setKeyStoreBean(CertWriterReader.KeyStoreBean keyStoreBean) {
        this.keyStoreBean = keyStoreBean;
        return this;
    }

    public InputStream getDataIN() {
        return dataIN;
    }

    public SigningBean setDataIN(InputStream dataIN) {
        this.dataIN = dataIN;
        return this;
    }

    public File getDataINPath() {
        return dataINPath;
    }

    public SigningBean setDataINPath(File dataINPath) {
        this.dataINPath = dataINPath;
        return this;
    }

    public InputStream getCertIN() {
        return certIN;
    }

    public SigningBean setCertIN(InputStream certIN) {
        this.certIN = certIN;
        return this;
    }

    public DataSource getOutputDS() {
        return outputDS;
    }

    public SigningBean setOutputDS(DataSource outputDS) {
        this.outputDS = outputDS;
        return this;
    }

    public String getOutputPath() {
        return outputPath;
    }

    public SigningBean setOutputPath(String outputPath) {
        this.outputPath = outputPath;
        return this;
    }

    public Mode getSigningMode() {
        return signingMode;
    }

    public SigningBean setSigningMode(Mode signingMode) {
        this.signingMode = signingMode;
        return this;
    }

    public SigningType getSignatureType() {
        return signatureType;
    }

    public SigningBean setSignatureType(SigningType signatureType) {
        this.signatureType = signatureType;
        return this;
    }

    public DigestAlg getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public SigningBean setDigestAlgorithm(DigestAlg digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
        return this;
    }

    public SignatureAlg getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public SigningBean setSignatureAlgorithm(SignatureAlg signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    public CryptoAlg getCryptoAlgorithm() {
        return cryptoAlgorithm;
    }

    public SigningBean setCryptoAlgorithm(CryptoAlg cryptoAlgorithm) {
        this.cryptoAlgorithm = cryptoAlgorithm;
        return this;
    }

    public DataSource getDataSource() {
        return dataSource;
    }

    public SigningBean setDataSource(DataSource dataSource) {
        this.dataSource = dataSource;
        return this;
    }

    public String getTspURL() {
        return tspURL;
    }

    public SigningBean setTspURL(String tspURL) {
        this.tspURL = tspURL;
        return this;
    }

    public List<TrustListWalkerAndGetter> getWalker() {
        return walker;
    }

    public SigningBean setWalker(List<TrustListWalkerAndGetter> walker) {
        this.walker = walker;
        return this;
    }
}

