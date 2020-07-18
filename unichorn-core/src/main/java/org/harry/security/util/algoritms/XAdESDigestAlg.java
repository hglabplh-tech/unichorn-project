package org.harry.security.util.algoritms;


import iaik.asn1.structures.AlgorithmID;

public enum XAdESDigestAlg {
    SHA256(DigestMethod.SHA256, AlgorithmID.sha256),
    SHA384(DigestMethod.SHA384, AlgorithmID.sha384),
    SHA512(DigestMethod.SHA512, AlgorithmID.sha512),
    RIPEMD160(DigestMethod.RIPEMD160, AlgorithmID.ripeMd160),
    SHA3_224(DigestMethod.SHA3_224, AlgorithmID.sha3_224),
    SHA3_256(DigestMethod.SHA3_256, AlgorithmID.sha3_256),
    SHA3_384(DigestMethod.SHA3_384, AlgorithmID.sha3_384),
    SHA3_512(DigestMethod.SHA3_512, AlgorithmID.sha3_512);

    private final String constantName;

    private final AlgorithmID algorithm;

    XAdESDigestAlg(String constantName, AlgorithmID algorithm) {

        this.constantName = constantName;
        this.algorithm = algorithm;
    }

    public String getConstantName() {
        return constantName;
    }

    public AlgorithmID getAlgorithm() {
        return algorithm;
    }

    public static XAdESDigestAlg getByName(String algorithmName) {
        for (XAdESDigestAlg alg: XAdESDigestAlg.values()) {
            if (alg.constantName.equals(algorithmName)) {
                return alg;
            }
        }
        return null;
    }
}