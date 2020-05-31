package org.harry.security.pkcs11.provider;

import org.harry.security.pkcs11.CardSigner;
import org.harry.security.util.ConfigReader;
import org.harry.security.util.SigningUtil;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.GSON;
import org.harry.security.util.trustlist.TrustListManager;
import org.junit.Ignore;
import org.junit.Test;

import javax.activation.DataSource;
import java.io.File;
import java.io.InputStream;
import java.util.List;

import static org.harry.security.CommonConst.TSP_URL;

public class CardSignerTest {

    @Test
    public void testSimpleSigningCAdES() throws Exception {
        InputStream input = CardSignerTest.class.getResourceAsStream("/test.txt");
        File tempFile = File.createTempFile("data.txt", ".pkcs7");
        SigningBean signingBean = new SigningBean().setDataIN(input)
                .setOutputPath(tempFile.getAbsolutePath())
                .setSignatureType(SigningBean.SigningType.CAdES)
                .setSigningMode(SigningBean.Mode.EXPLICIT);
        CardSigner signer = new CardSigner();
        String cardPIN  = getSmartCardPIN();
        signer.readCardData();
        signer.getKeyStore(cardPIN);
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        DataSource ds = signer.sign(signingBean, false, walkers);
        SigningUtil util = new SigningUtil();
        util.writeToFile(ds, signingBean);
        signer.releaseResource();
    }

    @Test
    public void testSimpleSigningPAdES() throws Exception {
        InputStream input = CardSignerTest.class.getResourceAsStream("/no-signatures.pdf");
        File tempFile = File.createTempFile("data", ".pdf");
        SigningBean signingBean = new SigningBean().setDataIN(input)
                .setOutputPath(tempFile.getAbsolutePath())
                .setTspURL("http://zeitstempel.dfn.de")
                .setSignatureType(SigningBean.SigningType.PAdES)
                .setSigningMode(SigningBean.Mode.EXPLICIT);
        CardSigner signer = new CardSigner();
        String cardPIN  = getSmartCardPIN();
        signer.readCardData();
        signer.getKeyStore(cardPIN);
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        DataSource ds = signer.sign(signingBean, false, walkers);
        SigningUtil util = new SigningUtil();
        util.writeToFile(ds, signingBean);
        signer.releaseResource();
    }


    @Test
    @Ignore
    public void testSetPIN() throws Exception {
        CardSigner signer = new CardSigner();
        String cardPIN  = getSmartCardPIN();
        signer.setPIN(cardPIN, cardPIN);
    }


    @Test
    public void testSimpleSigningCMS() throws Exception {
        InputStream input = CardSignerTest.class.getResourceAsStream("/test.txt");
        File tempFile = File.createTempFile("data.txt", ".pkcs7");
        SigningBean signingBean = new SigningBean().setDataIN(input)
                .setOutputPath(tempFile.getAbsolutePath())
                .setSignatureType(SigningBean.SigningType.CMS)
                .setSigningMode(SigningBean.Mode.EXPLICIT);
        CardSigner signer = new CardSigner();
        String cardPIN  = getSmartCardPIN();
        signer.readCardData();
        signer.getKeyStore(cardPIN);
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        DataSource ds = signer.sign(signingBean, false, walkers);
        SigningUtil util = new SigningUtil();
        util.writeToFile(ds, signingBean);
        signer.releaseResource();
    }

    private String getSmartCardPIN() {
        String pkcs11Pin = System.getenv("PKCS11PIN");
        ConfigReader.MainProperties props = ConfigReader.loadStore();
        String cardPIN;
        if (pkcs11Pin != null) {
            cardPIN = pkcs11Pin;
        } else {
            cardPIN = props.getPkcs11Pin();
        }
        return cardPIN.trim();
    }
}
