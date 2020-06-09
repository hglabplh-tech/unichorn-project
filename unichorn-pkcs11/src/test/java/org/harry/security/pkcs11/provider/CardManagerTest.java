package org.harry.security.pkcs11.provider;

import iaik.x509.X509Certificate;
import iaik.x509.attr.AttributeCertificate;
import org.harry.security.pkcs11.CardManager;
import org.harry.security.util.ConfigReader;
import org.harry.security.util.SigningUtil;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.trustlist.TrustListManager;
import org.junit.Ignore;
import org.junit.Test;

import javax.activation.DataSource;
import java.io.File;
import java.io.InputStream;
import java.util.List;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class CardManagerTest {

    @Test
    public void testSimpleSigningCAdES() throws Exception {
        InputStream input = CardManagerTest.class.getResourceAsStream("/test.txt");
        File tempFile = File.createTempFile("data.txt", ".pkcs7");
        SigningBean signingBean = new SigningBean().setDataIN(input)
                .setOutputPath(tempFile.getAbsolutePath())
                .setSignatureType(SigningBean.SigningType.CAdES)
                .setSigningMode(SigningBean.Mode.EXPLICIT);
        CardManager signer = new CardManager();
        String cardPIN  = getSmartCardPIN();
        signer.readCardData(cardPIN);
        signer.getKeyStore(cardPIN);
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        DataSource ds = signer.sign(signingBean, false, walkers);
        SigningUtil util = new SigningUtil();
        util.writeToFile(ds, signingBean);
        signer.releaseResource();
    }

    @Test
    public void testSimpleSigningPAdES() throws Exception {
        InputStream input = CardManagerTest.class.getResourceAsStream("/no-signatures.pdf");
        File tempFile = File.createTempFile("data", ".pdf");
        SigningBean signingBean = new SigningBean().setDataIN(input)
                .setOutputPath(tempFile.getAbsolutePath())
                .setTspURL("http://zeitstempel.dfn.de")
                .setSignatureType(SigningBean.SigningType.PAdES)
                .setSigningMode(SigningBean.Mode.EXPLICIT);
        CardManager signer = new CardManager();
        String cardPIN  = getSmartCardPIN();
        signer.readCardData(cardPIN);
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
        CardManager signer = new CardManager();
        String cardPIN  = getSmartCardPIN();
        signer.setPIN(cardPIN, cardPIN);
    }


    @Test
    public void testSimpleSigningCMS() throws Exception {
        InputStream input = CardManagerTest.class.getResourceAsStream("/test.txt");
        File tempFile = File.createTempFile("data.txt", ".pkcs7");
        SigningBean signingBean = new SigningBean().setDataIN(input)
                .setOutputPath(tempFile.getAbsolutePath())
                .setSignatureType(SigningBean.SigningType.CMS)
                .setSigningMode(SigningBean.Mode.EXPLICIT);
        CardManager signer = new CardManager();
        String cardPIN  = getSmartCardPIN();
        signer.readCardData(cardPIN);
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

    @Test
    public void testReadCardData() throws Exception {
        CardManager signer = new CardManager();
        String cardPIN  = getSmartCardPIN();
        signer.readCardData(cardPIN);
        List<X509Certificate> certs = signer.getCertificates();
        List<AttributeCertificate> attrCerts = signer.getAttrCertificates();
        List<iaik.pkcs.pkcs11.objects.PublicKey> pubKeys = signer.getPublicKeys();
        assertNotNull(certs);
        assertNotNull(attrCerts);
        assertTrue((certs.size() > 0));
        assertTrue((pubKeys.size() > 0));
        signer.releaseResource();
    }
}
