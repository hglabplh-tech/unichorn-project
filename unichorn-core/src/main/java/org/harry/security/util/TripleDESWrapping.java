package org.harry.security.util;

import iaik.utils.CryptoUtils;
import iaik.utils.Util;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;


    /**
     * This example demonstrates the use of the CMS TripleDES Key wrap cipher.
     * <p>
     * This example shows how this API can be used to encrypt a symmetric TripleDES
     * content encryption key with a TripleDES key encryption key as defined by
     * RFC 2630 (Cryptographic Message Syntax - CMS).
     * @version File Revision <!-- $$Revision: --> 12 <!-- $ -->
     */
    public class TripleDESWrapping  {

        // static variables defining conventions previously agreed upon,
        // i.e. the algorithms to use
        private final static String keyWrapAlgorithm = "3DESWrap3DES";
        private final static int keyType = Cipher.SECRET_KEY;
        private final static String keyAlgorithm = "DESede";

        public TripleDESWrapping() {
            // empty
        }

        public static byte[]  encrypt(String password, byte [] b) throws Exception  {
            Key kek = new SecretKeySpec(b, keyAlgorithm);
            Key keyToWrap = new SecretKeySpec(b, keyAlgorithm);
            System.out.println("Key to wrap:");
            System.out.println(Util.toString(keyToWrap.getEncoded()));

            // encrypt something with the original key
            Cipher cec = Cipher.getInstance("3DES/CBC/PKCS5Padding", "IAIK");
            cec.init(Cipher.ENCRYPT_MODE, keyToWrap);
            byte[] plain = password.getBytes();
            byte[] encrypted = cec.doFinal(plain);
            byte[] iv = cec.getIV();

            // wrap the key
            Cipher cipher1 = Cipher.getInstance(keyWrapAlgorithm, "IAIK");
            cipher1.init(Cipher.WRAP_MODE, kek);
            byte[] wrappedKey = cipher1.wrap(keyToWrap);
            System.out.println("Wrapped key:");
            System.out.println(Util.toString(wrappedKey));

            keyToWrap = new SecretKeySpec(wrappedKey, keyAlgorithm);
            System.out.println("Key to wrap:");
            System.out.println(Util.toString(keyToWrap.getEncoded()));

            // encrypt something with the original key
            cec = Cipher.getInstance("3DES/CBC/PKCS5Padding", "IAIK");
            cec.init(Cipher.ENCRYPT_MODE, kek);
            encrypted = cec.doFinal(wrappedKey);
            iv = cec.getIV();


            return encrypted;


        }

        public static byte[] getMaster() {
            SecureRandom random = new SecureRandom();
            random.setSeed(8787689698790790987L);
            // generate the TripleDES Key Encryption Key (KEK)
            byte[] b = new byte[24];
            random.nextBytes(b);
            return b;
        }

}


