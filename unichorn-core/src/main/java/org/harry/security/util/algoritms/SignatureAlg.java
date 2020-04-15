package org.harry.security.util.algoritms;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;

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
            AlgorithmID.sha3_512WithRSAEncryption.getAlgorithm()),

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
