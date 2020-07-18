package org.harry.security.util.algoritms;

import iaik.asn1.structures.AlgorithmID;
import iaik.xml.crypto.XmldsigMore;

public enum XAdESSigAlg {
    SIGNATURE_RSA_RIPEMD160(XmldsigMore.SIGNATURE_RSA_RIPEMD160
            , AlgorithmID.rsaSignatureWithRipemd160),
    SIGNATURE_RSA_RIPEMD160_ERRATA(XmldsigMore.SIGNATURE_RSA_RIPEMD160_ERRATA
            , AlgorithmID.rsaSignatureWithRipemd160),
    SIGNATURE_HMAC_SHA224(XmldsigMore.SIGNATURE_HMAC_SHA224
            , AlgorithmID.sha224WithRSAEncryption),
    SIGNATURE_HMAC_SHA256(XmldsigMore.SIGNATURE_HMAC_SHA256
            , AlgorithmID.sha256WithRSAEncryption),
    SIGNATURE_HMAC_SHA384(XmldsigMore.SIGNATURE_HMAC_SHA384
            , AlgorithmID.sha384WithRSAEncryption),
    SIGNATURE_HMAC_SHA512(XmldsigMore.SIGNATURE_HMAC_SHA512
            , AlgorithmID.sha512WithRSAEncryption),
    SIGNATURE_HMAC_RIPEMD160(XmldsigMore.SIGNATURE_HMAC_RIPEMD160,
            AlgorithmID.rsaSignatureWithRipemd160),
    SIGNATURE_ECDSA_SHA224(XmldsigMore.SIGNATURE_ECDSA_SHA224,
            AlgorithmID.ecdsa_plain_With_SHA224),
    SIGNATURE_ECDSA_SHA256(XmldsigMore.SIGNATURE_ECDSA_SHA256,
            AlgorithmID.ecdsa_plain_With_SHA256),
    SIGNATURE_ECDSA_SHA384(XmldsigMore.SIGNATURE_ECDSA_SHA384,
            AlgorithmID.ecdsa_plain_With_SHA384),
    SIGNATURE_ECDSA_SHA512(XmldsigMore.SIGNATURE_ECDSA_SHA512,
            AlgorithmID.ecdsa_plain_With_SHA512),
    SIGNATURE_ECDSA_RIPEMD160(XmldsigMore.SIGNATURE_ECDSA_RIPEMD160,
            AlgorithmID.ecdsa_plain_With_RIPEMD160),
    SIGNATURE_RSA_SSA_PSS(XmldsigMore.SIGNATURE_RSA_SSA_PSS,
            AlgorithmID.rsassaPss),
    SIGNATURE_RSA_SHA224_MGF1(XmldsigMore.SIGNATURE_RSA_SHA224_MGF1,
            AlgorithmID.sha224WithRSAEncryption),
    SIGNATURE_RSA_SHA256_MGF1(XmldsigMore.SIGNATURE_RSA_SHA256_MGF1,
            AlgorithmID.sha256WithRSAEncryption),
    SIGNATURE_RSA_SHA384_MGF1(XmldsigMore.SIGNATURE_RSA_SHA384_MGF1,
            AlgorithmID.sha384WithRSAEncryption),
    SIGNATURE_RSA_SHA512_MGF1(XmldsigMore.SIGNATURE_RSA_SHA512_MGF1,
            AlgorithmID.sha512WithRSAEncryption),
    SIGNATURE_RSA_SHA224(XmldsigMore.SIGNATURE_RSA_SHA224
            ,AlgorithmID.sha224WithRSAEncryption),
    SIGNATURE_RSA_SHA256(XmldsigMore.SIGNATURE_RSA_SHA256
            ,AlgorithmID.sha256WithRSAEncryption),
    SIGNATURE_RSA_SHA384(XmldsigMore.SIGNATURE_RSA_SHA384
            ,AlgorithmID.sha384WithRSAEncryption),
    SIGNATURE_RSA_SHA512(XmldsigMore.SIGNATURE_RSA_SHA512
            ,AlgorithmID.sha512WithRSAEncryption);



    private final AlgorithmID algorithm;

    private final String constantName;

    XAdESSigAlg(String constantName, AlgorithmID algorithm) {

        this.constantName = constantName;
        this.algorithm = algorithm;
    }

    public String getConstantName() {
        return constantName;
    }

    public AlgorithmID getAlgorithm() {
        return algorithm;
    }

    public static XAdESSigAlg getByName(String algorithmName) {
        for (XAdESSigAlg alg: XAdESSigAlg.values()) {
            if (alg.constantName.equals(algorithmName)) {
                return alg;
            }
        }
        return null;
    }
}
