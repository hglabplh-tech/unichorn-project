package org.harry.security.util.algoritms;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import oasis.names.tc.opendocument.xmlns.manifest._1.Algorithm;

public enum SignatureAlg {
    SHA_WITH_RSA(AlgorithmID.sha1WithRSAEncryption,
            "sha1WithRSAEncryption",
            AlgorithmID.sha1WithRSAEncryption.getAlgorithm()),
    SHA224_WITH_RSA(AlgorithmID.sha224WithRSAEncryption,
            "sha224WithRSAEncryption",
            AlgorithmID.sha224WithRSAEncryption.getAlgorithm()),
    SHA256_WITH_RSA(AlgorithmID.sha256WithRSAEncryption,
            "sha256WithRSAEncryption",
            AlgorithmID.sha256WithRSAEncryption.getAlgorithm()),
    SHA512_WITH_RSA(
            AlgorithmID.sha512WithRSAEncryption,
            "sha512WithRSAEncryption",
            AlgorithmID.sha512WithRSAEncryption.getAlgorithm()),
    SHA3_224_WITH_RSA(AlgorithmID.sha3_224WithRSAEncryption,
            "sha3_224WithRSAEncryption",
            AlgorithmID.sha3_224WithRSAEncryption.getAlgorithm()),
    SHA3_256_WITH_RSA(AlgorithmID.sha3_256WithRSAEncryption,
            "sha3_256WithRSAEncryption",
            AlgorithmID.sha3_256WithRSAEncryption.getAlgorithm()),
    SHA3_512_WITH_RSA(AlgorithmID.sha3_512WithRSAEncryption,
            "sha3_512WithRSAEncryption",
            AlgorithmID.sha3_512WithRSAEncryption.getAlgorithm()), //SHA1withDSA
    DSA_WITH_SHA1(AlgorithmID.dsaWithSHA1,
            "dsaWithSHA1",AlgorithmID.dsaWithSHA1.getAlgorithm()),
    DSA_WITH_SHA224(AlgorithmID.dsaWithSHA224,
            "dsaWithSHA224",AlgorithmID.dsaWithSHA224.getAlgorithm()),
    DSA_WITH_SHA256(AlgorithmID.dsaWithSHA256,
            "dsaWithSHA256", AlgorithmID.dsaWithSHA256.getAlgorithm()),
    DSA_WITH_SHA3_256(AlgorithmID.dsaWithSHA3_256,
            "dsaWithSHA3_256", AlgorithmID.dsaWithSHA3_256.getAlgorithm()),
    DSA_WITH_SHA3_384(AlgorithmID.dsaWithSHA3_384,
            "dsaWithSHA3_384", AlgorithmID.dsaWithSHA3_384.getAlgorithm()),
    DSA_WITH_SHA3_512(AlgorithmID.dsaWithSHA3_512,
            "dsaWithSHA3_512", AlgorithmID.dsaWithSHA3_512.getAlgorithm()),
    ECDSA_WITH_SHA1(AlgorithmID.ecdsa_With_SHA1,
            "ecdsa_With_SHA1",AlgorithmID.ecdsa_With_SHA1.getAlgorithm()),
    ECDSA_WITH_SHA224(AlgorithmID.ecdsa_With_SHA224,
            "ecdsa_With_SHA224",AlgorithmID.ecdsa_With_SHA224.getAlgorithm()),
    ECDSA_WITH_SHA256(AlgorithmID.ecdsa_With_SHA256,
            "ecdsa_With_SHA256", AlgorithmID.ecdsa_With_SHA256.getAlgorithm()),
    ECDSA_WITH_SHA3_256(AlgorithmID.ecdsa_With_SHA3_256,
            "ecdsa_With_SHA3_256", AlgorithmID.ecdsa_With_SHA3_256.getAlgorithm()),
    ECDSA_WITH_SHA3_384(AlgorithmID.ecdsa_With_SHA3_384,
            "ecdsa_With_SHA3_384", AlgorithmID.ecdsa_With_SHA3_384.getAlgorithm()),
    ECDSA_WITH_SHA3_512(AlgorithmID.ecdsa_With_SHA3_512,
            "ecdsa_With_SHA3_512", AlgorithmID.ecdsa_With_SHA3_512.getAlgorithm()),

    ;


    private final AlgorithmID algId;
    private final String name;
    private final ObjectID aoid;



    SignatureAlg(AlgorithmID algId, String name, ObjectID aoid) {
        this.algId = algId;
        this.name = name;
        this.aoid = aoid;
    }

    public AlgorithmID getAlgId() {
        return algId;
    }

    public String getName() {
        return name;
    }

    public ObjectID getAoid() {
        return aoid;
    }
}
