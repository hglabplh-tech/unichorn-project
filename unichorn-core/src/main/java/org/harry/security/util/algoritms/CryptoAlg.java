package org.harry.security.util.algoritms;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;

public enum CryptoAlg {
    AES_256_CBC(AlgorithmID.aes256_CBC,"AES-256-CBC", AlgorithmID.aes256_CBC.getAlgorithm()),
    AES_128_CBC(AlgorithmID.aes128_CBC,"AES-128-CBC", AlgorithmID.aes128_CBC.getAlgorithm()),
    AES_192_CBC(AlgorithmID.aes192_CBC, "AES-192-CBC", AlgorithmID.aes192_CBC.getAlgorithm()),
    DES_CBC(AlgorithmID.des_CBC, "DES-CBC", AlgorithmID.des_CBC.getAlgorithm()),
    DES_EDE3_CBC(AlgorithmID.des_EDE3_CBC, "DES-EDE3-CBC", AlgorithmID.des_EDE3_CBC.getAlgorithm()),
    PBE_SHAA3_KEY_TRIPLE_DES_CBC(AlgorithmID.pbeWithSHAAnd3_KeyTripleDES_CBC,"PBE-SHAA3-KEY-TRIPLE-DES-CBC",
            AlgorithmID.pbeWithSHAAnd3_KeyTripleDES_CBC.getAlgorithm()),
    PBE_SHAA_40BITSRC2_CBC(AlgorithmID.pbeWithSHAAnd40BitRC2_CBC,"PBE-SHAA-40BITSRC2_CBC",
            AlgorithmID.pbeWithSHAAnd40BitRC2_CBC.getAlgorithm()),
    PBE_SHAA_40BITSRC4(AlgorithmID.pbeWithSHAAnd40BitRC4,"PBE-SHAA-40BITSRC4",
                       AlgorithmID.pbeWithSHAAnd40BitRC4.getAlgorithm()),
    PBE_SHAA_128BITSRC2_CBC(AlgorithmID.pbeWithSHAAnd128BitRC2_CBC,"PBE-SHAA-128BITSRC2_CBC",
                       AlgorithmID.pbeWithSHAAnd128BitRC2_CBC.getAlgorithm()),
    PBE_SHAA_128BITSRC4(AlgorithmID.pbeWithSHAAnd128BitRC4,"PBE-SHAA-128BITSRC2_CBC",
            AlgorithmID.pbeWithSHAAnd128BitRC4.getAlgorithm())

    ;

    private final AlgorithmID algId;
    private final String name;
    private final ObjectID aoid;

    CryptoAlg(AlgorithmID algId, String name, ObjectID aoid) {
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
