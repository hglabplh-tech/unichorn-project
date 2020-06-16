package org.harry.security.util.algoritms;

import iaik.xml.crypto.XmldsigMore;

public enum XAdESSigAlg {
    SIGNATURE_RSA_RIPEMD160(XmldsigMore.SIGNATURE_RSA_RIPEMD160),
    SIGNATURE_RSA_RIPEMD160_ERRATA(XmldsigMore.SIGNATURE_RSA_RIPEMD160_ERRATA),
    SIGNATURE_HMAC_SHA224(XmldsigMore.SIGNATURE_HMAC_SHA224),
    SIGNATURE_HMAC_SHA256(XmldsigMore.SIGNATURE_HMAC_SHA256),
    SIGNATURE_HMAC_SHA384(XmldsigMore.SIGNATURE_HMAC_SHA384),
    SIGNATURE_HMAC_SHA512(XmldsigMore.SIGNATURE_HMAC_SHA512),
    SIGNATURE_HMAC_RIPEMD160(XmldsigMore.SIGNATURE_HMAC_RIPEMD160),
    SIGNATURE_HMAC_MD5(XmldsigMore.SIGNATURE_HMAC_MD5),
    SIGNATURE_ECDSA_SHA1(XmldsigMore.SIGNATURE_ECDSA_SHA1),
    SIGNATURE_ECDSA_SHA224(XmldsigMore.SIGNATURE_ECDSA_SHA224),
    SIGNATURE_ECDSA_SHA256(XmldsigMore.SIGNATURE_ECDSA_SHA256),
    SIGNATURE_ECDSA_SHA384(XmldsigMore.SIGNATURE_ECDSA_SHA384),
    SIGNATURE_ECDSA_SHA512(XmldsigMore.SIGNATURE_ECDSA_SHA512),
    SIGNATURE_ECDSA_RIPEMD160(XmldsigMore.SIGNATURE_ECDSA_RIPEMD160),
    SIGNATURE_RSA_SSA_PSS(XmldsigMore.SIGNATURE_RSA_SSA_PSS),
    SIGNATURE_RSA_SHA224_MGF1(XmldsigMore.SIGNATURE_RSA_SHA224_MGF1),
    SIGNATURE_RSA_SHA256_MGF1(XmldsigMore.SIGNATURE_RSA_SHA256_MGF1),
    SIGNATURE_RSA_SHA384_MGF1(XmldsigMore.SIGNATURE_RSA_SHA384_MGF1),
    SIGNATURE_RSA_SHA512_MGF1(XmldsigMore.SIGNATURE_RSA_SHA512_MGF1),
    SIGNATURE_RSA_RIPEMD128_MGF1(XmldsigMore.SIGNATURE_RSA_RIPEMD128_MGF1),
    SIGNATURE_RSA_RIPEMD160_MGF1(XmldsigMore.SIGNATURE_RSA_RIPEMD160_MGF1),
    SIGNATURE_RSA_WHIRLPOOL_MGF1(XmldsigMore.SIGNATURE_RSA_WHIRLPOOL_MGF1);

    private final String constantName;

    XAdESSigAlg(String constantName) {
        this.constantName = constantName;
    }

    public String getConstantName() {
        return constantName;
    }
}
