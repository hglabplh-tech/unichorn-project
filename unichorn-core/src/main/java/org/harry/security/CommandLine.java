package org.harry.security;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

public class CommandLine {

   @Parameters(commandDescription = "The parameters valid for all commands")
    public static class MainCommands {
       @Parameter(names={"--runCommand", "-r"}, description = "The command to be executed", required = true )
       private CMSSigner.Commands command;
       @Parameter(names={"--dataFile", "-f"}, description = "The data file to be signed")
       private String dataFileName;
       @Parameter(names={"--outFile", "-o"}, description = "The signature file output")
       private String outFileName;
       @Parameter(names={"--config", "-c"}, description= "The configuration properties path", required = false)
       private String configFileName;

       @Parameter(names = "--help", help = true)
       private boolean help = false;
       @Parameter(names = {"--url", "-u"}, description = "The URL to check")
       private String httpsURL;
       @Parameter(names = {"--ocspCheck"}, description = "The URL certificate is checked against OCSP in addition")
       private boolean ocspCheck = false;

       public boolean isOcspCheck() {
           return ocspCheck;
       }

       public String getHttpsURL() {
           return httpsURL;
       }

       public CMSSigner.Commands getCommand() {
           return command;
       }

       public String getDataFileName() {
           return dataFileName;
       }

       public String getOutFileName() {
           return outFileName;
       }

       public String getConfigFileName() {
           return configFileName;
       }

       public boolean isHelp() {
           return help;
       }

       public boolean isEncrypt() {
           return encrypt;
       }

       @Parameter(names= {"--encrypt", "-e"}, description = "Encryption is processed when do SIGN")
       private boolean encrypt = false;


   }

   @Parameters(commandDescription = "The certificates are loaded from windows key-store")
    public static class LoadCerts {

   }

   @Parameters(commandDescription = "commands for signing")
   public static class SigningCmd{
       @Parameter(names = {"--signImplicit", "-i"}, description = "The mode used for signing")
       private boolean implicit = false;
       @Parameter(names = {"--inCert", "-X"}, description = "The signed cert used for signing")
       private String inCert;
       @Parameter(names = {"--sigType", "-t"}, description = "The type used for signing")
       private CMSSigner.SigType type = CMSSigner.SigType.CMS;


       public String getInCert() {
           return inCert;
       }

       public boolean isImplicit() {
           return implicit;
       }

       public CMSSigner.SigType getType() {
           return type;
       }
   }

   @Parameters(commandDescription = "This command is to sign a certificate")
    public static class SignCert {





   }

    @Parameters(commandDescription = "This command is to sign a certificate")
    public static class SignWithSignedCert {

        @Parameter(names= {"--alias", "-a"}, description = "additional alias for signing certificate using GET_SIGNED_CERT_SIGN")
        private String alias;



        public String getAlias() {
            return alias;
        }


    }
    @Parameters(commandDescription = "Command for vedrifying a signed data signature")
    public static class VerifyCommand {

       @Parameter(names = {"--sigInput", "-s"} , description = "input file which is a cms signature file")
       private String signatureFilename;

        @Parameter(names = {"--sigData", "-d"} , description = "input data file which is the signed data")
        private String dataFilename = null;

        public String getDataFilename() {
            return dataFilename;
        }

        public String getSignatureFilename() {
            return signatureFilename;
        }
    }
}
