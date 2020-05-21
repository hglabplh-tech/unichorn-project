package org.harry.security;

import com.beust.jcommander.JCommander;
import iaik.cms.SecurityProvider;
import iaik.cms.SignedDataStream;
import iaik.cms.ecc.ECCelerateProvider;
import iaik.security.ec.provider.ECCelerate;

import iaik.security.provider.IAIKMD;
import iaik.security.random.MetaSeedGenerator;
import iaik.security.random.SeedGenerator;
import iaik.x509.X509Certificate;
import org.harry.security.util.*;
import org.harry.security.util.bean.SigningBean;
import org.harry.security.util.certandkey.CertWriterReader;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.harry.security.util.trustlist.TrustListManager;


import javax.activation.DataSource;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Collection;
import java.util.List;
import java.util.Random;

import static org.harry.security.util.CertificateWizzard.generateThis;
import static org.harry.security.util.certandkey.CertWriterReader.loadSecrets;

public class CMSSigner {

    public enum Commands {
        SIGN("sign"),
        GEN_KEYSTORE("genKeyStore"),
        ENCRYPT("encrypt"),
        ENCRYPT_SIGN("encrypt_sign"),
        DECRYPT("decrypt"),
        DECRYPT_SIGNED("decrypt_SIGNED"),
        LOAD_CERTS("loadCerts"),
        CRYPT_ENVELOP("cryptEnvelop"),
        DECRYPT_ENVELOP("decryptEnvelop"),
        SIGN_CERT("signCert"),
        GET_SIGNED_CERT_SIGN("getSignedCertAndSign"),
        VERIFY_SIGNATURE("verifySignature"),
        HTTPS_CHECK("httpsCheck")
        ;

        public String getCommand() {
            return value;
        }

        private String value;
        Commands(String value) {
            this.value = value;
        }
    }

    public enum SigType {
        CMS,
        CAdES;
    }



    static CommandLine.MainCommands cmds = new CommandLine.MainCommands();
    static CommandLine.LoadCerts loadC = new CommandLine.LoadCerts();
    static CommandLine.SignCert signCert = new CommandLine.SignCert();
    static CommandLine.SignWithSignedCert signWith = new CommandLine.SignWithSignedCert();
    static CommandLine.SigningCmd signed = new CommandLine.SigningCmd();
    static CommandLine.VerifyCommand verify = new CommandLine.VerifyCommand();


    public static void main(String[] args) {
        CMSSigner signer = new CMSSigner();

        JCommander commander = JCommander.newBuilder()
                .addObject(cmds)
                .addObject(signed)
                .addObject(signCert)
                .addObject(signWith)
                .addObject(loadC)
                .addObject(verify)
                .build();
        commander.parse(args);
        if (cmds.isHelp()) {
            commander.usage();
            System.exit(0);
        }
        signer.run();

     }


    public void run() {
        setProviders();
        CertificateWizzard.initThis();
        Commands command = cmds.getCommand();
        ConfigReader.MainProperties params = ConfigReader.loadStore();
        List<TrustListManager> walkers = ConfigReader.loadAllTrusts();
        try {
            KeyStore store = KeyStoreTool.loadAppStore();
            Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
            CertWriterReader.KeyStoreBean bean = new
                    CertWriterReader.KeyStoreBean(keys.getSecond(), keys.getFirst());
            SigningBean signingBean = new SigningBean()
                    .setKeyStoreBean(bean)
                    .setSigningMode(SigningBean.Mode.EXPLICIT)
                    .setAlias(params.getAlias());


            if (command.equals(Commands.SIGN) || command.equals(Commands.DECRYPT)
                    || command.equals(Commands.CRYPT_ENVELOP)
                    || command.equals(Commands.DECRYPT_ENVELOP)
                    || command.equals(Commands.SIGN_CERT)
                    || command.equals(Commands.GET_SIGNED_CERT_SIGN)) {
                try {


                    int mode = SignedDataStream.EXPLICIT;
                    if (signed.isImplicit()) {
                        mode = SignedDataStream.IMPLICIT;
                    }
                    SigningUtil util = SigningUtil.newBuilder()
                            .withProperties(params)
                            .withKeystoreBean(bean)
                            .withSignaturePath(cmds.getOutFileName())
                            .withMode(mode).build();
                    FileInputStream dataStream = null;
                    String dataFileName = cmds.getDataFileName();
                    if (dataFileName != null) {
                        File input = new File(dataFileName).getAbsoluteFile();
                        dataStream =
                                new FileInputStream(input.getAbsolutePath());

                    }
                    signingBean = signingBean.setDataIN(dataStream)
                            .setOutputPath(cmds.getOutFileName());

                    if (!cmds.isEncrypt() && command.equals(Commands.SIGN)) {
                        DataSource signatureDS = util.signCMS(signingBean);
                        util.writeToFile(signatureDS, signingBean);
                    } else if (!cmds.isEncrypt() && command.equals(Commands.DECRYPT)) {
                        DataSource signatureDS = util.decryptCMS(signingBean);
                        util.writeToFile(signatureDS,signingBean);
                    } else if (cmds.isEncrypt() && command.equals(Commands.SIGN)) {
                        DataSource envelopDS = util.encryptCMS(signingBean);
                        util.writeToFile(envelopDS, signingBean);
                    } else if (command.equals(Commands.CRYPT_ENVELOP)) {
                        DataSource outDS = util.envelopeDataCMS(dataStream);
                        util.writeToFile(outDS, signingBean);
                    } else if (command.equals(Commands.DECRYPT_ENVELOP)) {
                        DataSource outDS = util.getEnvelopedData(dataStream);
                        util.writeToFile(outDS, signingBean);
                    } else if (command.equals(Commands.SIGN_CERT)) {

                        File certFile = new File(signed.getInCert()).getAbsoluteFile();
                        FileInputStream certFileStream = new FileInputStream(certFile);
                        signingBean.setDataIN(certFileStream);
                        DataSource ds = util.signCMS(signingBean);
                        util.writeToFile(ds, signingBean);
                    } else if (command.equals(Commands.GET_SIGNED_CERT_SIGN)) {
                        File certFile = new File(signed.getInCert()).getAbsoluteFile();
                        FileInputStream certFileStream = new FileInputStream(certFile);
                        signingBean.setCertIN(certFileStream);
                        signingBean.setSignedWithAlias(signWith.getAlias());
                        DataSource ds = util.signEncrCMS(signingBean);
                        util.writeToFile(ds, signingBean);
                    }

                } catch (IOException e) {
                    throw new IllegalStateException("keystore cannot be loaded", e);
                }
            } else if (command.equals(Commands.GEN_KEYSTORE)) {
                try {
                    GenerateKeyStore generator = new GenerateKeyStore(params);
                    generator.generateCertificates();
                } catch (Exception e) {
                    throw new IllegalStateException("error occured when generating keyStore", e);
                }
            } else if (command.equals(Commands.LOAD_CERTS)) {
                CertLoader.loadCertificatesFromWIN();
            } else if (command.equals(Commands.HTTPS_CHECK)) {
                String checkURL = cmds.getHttpsURL();
                HttpsChecker.checkHttpsCertValidity(checkURL, cmds.isOcspCheck(), false);
            } else if (command.equals(Commands.VERIFY_SIGNATURE)) {
                try {
                    File file = new File(verify.getSignatureFilename()).getAbsoluteFile();
                    FileInputStream stream = new FileInputStream(file);
                    FileInputStream data = null;
                    if (verify.getDataFilename() != null) {
                        File dataFile = new File(verify.getDataFilename()).getAbsoluteFile();
                        data = new FileInputStream(dataFile);
                    }

                    VerifyUtil util = new VerifyUtil(walkers, signingBean);

                    VerifyUtil.VerifierResult sigOk = util.verifyCMSSignature(stream, data);
                    List<VerifyUtil.SignerInfoCheckResults> results = sigOk.getSignersCheck();
                    boolean success = true;
                    for (VerifyUtil.SignerInfoCheckResults result : results) {
                        Collection<Tuple<String, VerifyUtil.Outcome>> sigRes = result.getSignatureResult().values();
                        for (Tuple<String, VerifyUtil.Outcome> tuple : sigRes) {
                            if (!tuple.getSecond().equals(VerifyUtil.Outcome.SUCCESS)
                                    && !tuple.getSecond().equals(VerifyUtil.Outcome.UNDETERMINED)) {
                                success = false;
                            }
                        }

                        Collection<Tuple<String, VerifyUtil.Outcome>> ocspRes = result.getOcspResult().values();
                        for (Tuple<String, VerifyUtil.Outcome> tuple : ocspRes) {
                            if (!tuple.getSecond().equals(VerifyUtil.Outcome.SUCCESS)
                            && !tuple.getSecond().equals(VerifyUtil.Outcome.UNDETERMINED)) {
                                success = false;
                            }
                        }


                        if (success) {
                            System.out.println("signature is checked ok");
                        } else {
                            System.out.println("signature is checked nok outcome is not ok");
                        }
                    }

                } catch (Exception ex) {
                    throw new IllegalStateException("command failed", ex);
                }
            }
        } catch (Exception ex) {
            throw new IllegalStateException("command failed", ex);
        }
    }



    private CertWriterReader.KeyStoreBean initKeyStoreBean(ConfigReader.MainProperties params) throws FileNotFoundException {
        FileInputStream
                keyStoreStream = new FileInputStream(params.getKeystorePath());
        return loadSecrets(keyStoreStream, params.getKeystoreType(),
                params.getKeystorePass(), params.getAlias());
    }

    public static void setProviders() {
        IAIKMD.addAsProvider();
        ECCelerate ecProvider = ECCelerate.getInstance();
        Security.insertProviderAt(ecProvider, 4);
        SecurityProvider.setSecurityProvider(new ECCelerateProvider());

    }

    public void initRandom() {
        System.out.println("Quick-starting random number generator (not for use in production systems!)...");
        Random random = new Random();
        byte[] seed = new byte[500];
        random.nextBytes(seed);
        MetaSeedGenerator.setSeed(seed);
        SeedGenerator.setDefault(MetaSeedGenerator.class);
    }
}
