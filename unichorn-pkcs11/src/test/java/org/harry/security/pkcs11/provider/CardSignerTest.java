package org.harry.security.pkcs11.provider;

import org.harry.security.pkcs11.CardSigner;
import org.harry.security.util.bean.SigningBean;
import org.junit.Test;

import java.io.InputStream;

public class CardSignerTest {

    @Test
    public void testSimpleSigning() throws Exception {
        InputStream input = CardSignerTest.class.getResourceAsStream("/test.txt");
        SigningBean signingBean = new SigningBean().setDataIN(input)
                .setSigningMode(SigningBean.Mode.EXPLICIT);
        CardSigner signer = new CardSigner();
        String cardPIN = "315631";
        signer.readCardData();
        signer.getKeyStore(cardPIN);
        signer.sign(signingBean);
    }
}
