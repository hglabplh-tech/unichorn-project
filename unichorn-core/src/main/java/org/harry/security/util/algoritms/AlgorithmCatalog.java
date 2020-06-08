package org.harry.security.util.algoritms;

import iaik.asn1.structures.AlgorithmID;
import oasis.names.tc.opendocument.xmlns.manifest._1.Algorithm;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class AlgorithmCatalog {

    private static int subtractYear = 1900;

    public static List<RSADefinition> rsaDefinitions =
            Arrays.asList(
                    new RSADefinition(512, 1899, new Date(2018 - subtractYear, 1, 1)),
                    new RSADefinition(1900, 2999, new Date(2021 - subtractYear, 1, 1)),
                    new RSADefinition(3000, 4096, new Date(2022 -subtractYear, 1, 1)),
                    new RSADefinition(4096, 20000, new Date(2030 - subtractYear, 1, 1))
            );

    public static List<DSADefinition> dsaDefinitions =
            Arrays.asList(
                    new DSADefinition(1024,160 , new Date(2018 - subtractYear, 1, 1)),
                    new DSADefinition(2048, 224, new Date(2020 - subtractYear, 1, 1)),
                    new DSADefinition(2048,256 , new Date(2022 - subtractYear, 1, 1)),
                    new DSADefinition(3072, 256, new Date(2030 - subtractYear, 1, 1))
            );

    public static List<ECDSADefinition> ecdsaDefinitions =
            Arrays.asList(
                    new ECDSADefinition(AlgorithmID.ecdsa_plain_With_RIPEMD160, new Date(2018 - subtractYear, 1, 1)),
                    new ECDSADefinition(AlgorithmID.ecdsa_plain_With_SHA224, new Date(2020 - subtractYear, 1, 1)),
                    new ECDSADefinition(AlgorithmID.ecdsa_With_SHA224, new Date(2020 - subtractYear, 1, 1)),
                    new ECDSADefinition(AlgorithmID.ecdsa_plain_With_SHA256 , new Date(2022 - subtractYear, 1, 1)),
                    new ECDSADefinition(AlgorithmID.ecdsa_plain_With_SHA384 , new Date(2022 - subtractYear, 1, 1)),
                    new ECDSADefinition(AlgorithmID.ecdsa_plain_With_SHA512 , new Date(2022 - subtractYear, 1, 1)),
                    new ECDSADefinition(AlgorithmID.ecdsa_With_SHA256 , new Date(2022 - subtractYear, 1, 1)),
                    new ECDSADefinition(AlgorithmID.ecdsa_With_SHA384 , new Date(2022 - subtractYear, 1, 1)),
                    new ECDSADefinition(AlgorithmID.ecdsa_With_SHA512 , new Date(2022 - subtractYear, 1, 1)),
                    new ECDSADefinition(AlgorithmID.ecdsa_plain_With_SHA384 , new Date(2022 - subtractYear, 1, 1)),
                    new ECDSADefinition(AlgorithmID.ecdsa_With_SHA3_224 , new Date(2020 - subtractYear, 1, 1)),
                    new ECDSADefinition(AlgorithmID.ecdsa_With_SHA3_256 , new Date(2022 - subtractYear, 1, 1)),
                    new ECDSADefinition(AlgorithmID.ecdsa_With_SHA3_384 , new Date(2022 - subtractYear, 1, 1)),
                    new ECDSADefinition(AlgorithmID.ecdsa_With_SHA3_512 , new Date(2022 - subtractYear, 1, 1))
            );

    public static List<SignatureDefinition> sigDefinitions =
            Arrays.asList(
                    new SignatureDefinition(AlgorithmID.sha1WithRSAEncryption, new Date(2006 - subtractYear, 1, 1)),
                    new SignatureDefinition(AlgorithmID.sha224WithRSAEncryption,  new Date(2018 - subtractYear, 1, 1)),
                    new SignatureDefinition(AlgorithmID.sha3_224WithRSAEncryption,  new Date(2018 - subtractYear, 1, 1)),
                    new SignatureDefinition(AlgorithmID.sha256WithRSAEncryption,  new Date(2022 - subtractYear, 1, 1)),
                    new SignatureDefinition(AlgorithmID.sha384WithRSAEncryption,  new Date(2022 - subtractYear, 1, 1)),
                    new SignatureDefinition(AlgorithmID.sha512WithRSAEncryption,  new Date(2022 - subtractYear, 1, 1)),
                    new SignatureDefinition(AlgorithmID.sha3_256WithRSAEncryption,  new Date(2022 - subtractYear, 1, 1)),
                    new SignatureDefinition(AlgorithmID.sha3_384WithRSAEncryption,  new Date(2022 - subtractYear, 1, 1)),
                    new SignatureDefinition(AlgorithmID.sha3_512WithRSAEncryption,  new Date(2022 - subtractYear, 1, 1))
            );

    public static List<DigestDefinition> digestDefinitions =
            Arrays.asList(
                    new DigestDefinition(AlgorithmID.sha1, new Date(2006 - subtractYear, 1, 1)),
                    new DigestDefinition(AlgorithmID.sha224,  new Date(2018 - subtractYear, 1, 1)),
                    new DigestDefinition(AlgorithmID.sha3_224,  new Date(2018 - subtractYear, 1, 1)),
                    new DigestDefinition(AlgorithmID.sha256,  new Date(2022 - subtractYear, 1, 1)),
                    new DigestDefinition(AlgorithmID.sha384,  new Date(2022 - subtractYear, 1, 1)),
                    new DigestDefinition(AlgorithmID.sha512,  new Date(2022 - subtractYear, 1, 1)),
                    new DigestDefinition(AlgorithmID.sha3_256,  new Date(2022 - subtractYear, 1, 1)),
                    new DigestDefinition(AlgorithmID.sha3_384,  new Date(2022 - subtractYear, 1, 1)),
                    new DigestDefinition(AlgorithmID.sha3_512,  new Date(2022 - subtractYear, 1, 1))
            );


    public static class DateDef {
        private final Date endDate;

        public DateDef(Date endDate) {
            this.endDate = endDate;
        }

        public Date getEndDate() {
            return endDate;
        }
    }


    public static class RSADefinition extends DateDef {

        private final int minLength;

        private final int maxLength;

        public RSADefinition(int minLength,int maxLength, Date endDate) {
            super(endDate);
            this.minLength = minLength;
            this.maxLength = maxLength;
        }

        public int getMinLength() {
            return minLength;
        }

        public int getMaxLength() {
            return maxLength;
        }


    }

    public static class DSADefinition extends DateDef {

        private final int p;

        private final int q;

        public DSADefinition(int p, int q, Date endDate) {
            super(endDate);
            this.p = p;
            this.q = q;
        }

        public int getP() {
            return p;
        }

        public int getQ() {
            return q;
        }
    }

    public static class ECDSADefinition extends DateDef {
        private final AlgorithmID algorithm;

        public ECDSADefinition(AlgorithmID algorithm, Date endDate) {
            super(endDate);
            this.algorithm = algorithm;
        }

        public AlgorithmID getAlgorithm() {
            return algorithm;
        }
    }

    public static class SignatureDefinition extends DateDef {
        private final AlgorithmID algorithm;

        public SignatureDefinition(AlgorithmID algorithm, Date endDate) {
            super(endDate);
            this.algorithm = algorithm;
        }

        public AlgorithmID getAlgorithm() {
            return algorithm;
        }
    }

    public static class DigestDefinition extends DateDef {
        private final AlgorithmID algorithm;

        public DigestDefinition(AlgorithmID algorithm, Date endDate) {
            super(endDate);
            this.algorithm = algorithm;
        }

        public AlgorithmID getAlgorithm() {
            return algorithm;
        }
    }


}
