package harry.security.responder.resources;

public class GSON {
    public static class Params {

        public String parmType;
        public Signing signing;
    }
    public static class Signing {
        public String signatureType = null;
        public int    mode = 0;
    }
}
