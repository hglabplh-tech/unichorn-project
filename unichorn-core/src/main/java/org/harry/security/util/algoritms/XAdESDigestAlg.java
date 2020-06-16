package org.harry.security.util.algoritms;




public enum XAdESDigestAlg {
    SHA256(DigestMethod.SHA256),
    SHA384(DigestMethod.SHA384),
    SHA512(DigestMethod.SHA512),
    RIPEMD160(DigestMethod.RIPEMD160),
    SHA3_224(DigestMethod.SHA3_224),
    SHA3_256(DigestMethod.SHA3_256),
    SHA3_384(DigestMethod.SHA3_384),
    SHA3_512(DigestMethod.SHA3_512);

    private final String constantName;

    XAdESDigestAlg(String constantName) {
        this.constantName = constantName;
    }

    public String getConstantName() {
        return constantName;
    }
}