package org.harry.security.util.certandkey;

public class GSON {
    public static class Params {

        public String parmType;
        public Signing signing;
    }
    public static class Signing {
        public String signatureType = null;
        public int    mode = 0;
        public String signatureAlgorithm = null;
        public String digestAlgorithm = null;
        public String attributeCert = null;
        public SigningCAdES cadesParams = null;

    }

    public static class SigningCAdES {
        public String TSAURL;
        public boolean addArchiveinfo = false;
    }
}
