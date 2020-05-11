package org.harry.security.util.algoritms;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;

public enum DigestAlg {
    SHA(AlgorithmID.sha, "SHA1", AlgorithmID.sha.getAlgorithm()),
    SHA224(AlgorithmID.sha224, "SHA-224", AlgorithmID.sha224.getAlgorithm()),
    SHA256(AlgorithmID.sha256, "SHA-256", AlgorithmID.sha256.getAlgorithm()),
    SHA512(AlgorithmID.sha512, "SHA-512", AlgorithmID.sha512.getAlgorithm()),
    SHA3_224(AlgorithmID.sha3_224, "SHA3-224", AlgorithmID.sha3_224.getAlgorithm()),
    SHA3_256(AlgorithmID.sha3_256, "SHA3-256", AlgorithmID.sha3_256.getAlgorithm()),
    SHA3_512(AlgorithmID.sha3_512, "SHA3-512", AlgorithmID.sha3_512.getAlgorithm()),

    ;

    private final AlgorithmID algId;
    private final String name;
    private final ObjectID aoid;



    DigestAlg(AlgorithmID algId, String name, ObjectID aoid) {
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

    public static DigestAlg getFromName(String name) {
        if (name != null) {
            for (DigestAlg alg : DigestAlg.values()) {
                if (alg.getName().equals(name)) {
                    return alg;
                }
            }
        }
        return null;
    }
}
