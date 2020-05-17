package org.harry.security.pkcs11;

import iaik.asn1.structures.AlgorithmID;
import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.objects.*;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.provider.*;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11Key;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11PrivateKey;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11PublicKey;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11SecretKey;
import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import iaik.pkcs.pkcs12.PKCS12;
import iaik.pkcs.pkcs12.PKCS12KeyStore;
import iaik.security.provider.IAIK;
import iaik.security.provider.IAIKMD;
import iaik.security.rsa.RSAPssPrivateKey;
import iaik.x509.X509Certificate;
import org.harry.security.pkcs11.provider.IAIKPkcs11Private;
import org.harry.security.util.CertificateWizzard;
import org.harry.security.util.Tuple;
import org.harry.security.util.certandkey.KeyStoreTool;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.mockito.stubbing.OngoingStubbing;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import sun.security.jca.GetInstance;
import sun.security.pkcs11.wrapper.PKCS11;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.ref.Reference;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.*;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.*;

import static org.mockito.Matchers.*;
import static org.powermock.api.mockito.PowerMockito.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest(fullyQualifiedNames = {"iaik.pkcs.pkcs11.Module",

        "sun.security.jca.GetInstance" })
public class ModuleSim {

    IAIKMD instanceMD = null;
    IAIKPkcs11Private provider = null;
    Certificate certificate;
    iaik.security.rsa.RSAPrivateKey key;
    TokenManager manager;
    KeyStore globalKeyStore;
    @Test
    public void testSlotList() throws Exception {
        provider = mockPKCS11Module();
        Security.insertProviderAt(instanceMD, 1);
        Security.insertProviderAt(IAIK.getInstance(), 2);
        Security.insertProviderAt(provider, 3);





        Module pkcs11Module = Module.getInstance("blubber");

        KeyStore keyStore = globalKeyStore;


            Enumeration<String> aliases = keyStore.aliases();
            pkcs11Module.initialize(null);


        try {
            Info info = pkcs11Module.getInfo();

            Slot[] slots = pkcs11Module.getSlotList(Module.SlotRequirement.ALL_SLOTS);



                Slot[] slotsWithToken = pkcs11Module
                        .getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
                Token[] tokens = new Token[slotsWithToken.length];

                for (int i = 0; i < slotsWithToken.length; i++) {

                    tokens[i] = slotsWithToken[i].getToken();
                    TokenInfo tokenInfo = tokens[i].getTokenInfo();

                    Mechanism[] supportedMechanisms = tokens[i].getMechanismList();
                    for (int j = 0; j < supportedMechanisms.length; j++) {

                        MechanismInfo mechanismInfo = tokens[i]
                                .getMechanismInfo(supportedMechanisms[j]);


                    }

                }



                for (int i = 0; i < tokens.length; i++) {
                    TokenInfo tokenInfo = tokens[i].getTokenInfo();
                    if (!tokenInfo.isTokenInitialized()) {
                        continue;
                    }
                    Session session = tokens[i].openSession(Token.SessionType.SERIAL_SESSION,
                            Token.SessionReadWriteBehavior.RO_SESSION, null, null);

                    try {
                        if (tokenInfo.isLoginRequired()) {
                            if (tokenInfo.isProtectedAuthenticationPath()) {
                                session.login(Session.UserType.USER, null); // the token prompts the PIN by other
                                // means; e.g. PIN-pad
                            } else {
                                char[] pin = "123456".toCharArray();


                                if (pin != null) {
                                    // login user
                                    session.login(Session.UserType.USER, pin);
                                }
                            }
                        }
                        SessionInfo sessionInfo = session.getSessionInfo();


                        session.findObjectsInit(null);
                        Object[] objects = session.findObjects(1);

                        X509Certificate iaik = null;
                        CertificateFactory x509CertificateFactory = null;
                        int index = 0;
                        while (objects.length > 0) {
                            while (objects.length > index) {
                                Object object = objects[index];
                                index++;

                                if (object instanceof X509PublicKeyCertificate) {
                                    try {
                                        byte[] encodedCertificate = ((X509PublicKeyCertificate) object)
                                                .getValue().getByteArrayValue();
                                        if (x509CertificateFactory == null) {
                                            x509CertificateFactory = CertificateFactory.getInstance("X.509");
                                        }
                                        certificate = x509CertificateFactory
                                                .generateCertificate(new ByteArrayInputStream(encodedCertificate));
                                        if (certificate != null) {
                                            iaik = new X509Certificate(certificate.getEncoded());
                                            System.out.println("Certificate: " + iaik.toString());
                                            System.out.println("Issuer : " + iaik.getIssuerDN().getName());
                                        }
                                    } catch (Exception ex) {
                                        ex.printStackTrace();
                                    }
                                } else if (object instanceof RSAPrivateKey) {
                                    try {
                                        RSAPrivateKey privateKey = ((RSAPrivateKey) object);

                                        iaik.security.rsa.RSAPrivateKey newPriv = null;
                                        Constructor[] ctors = iaik.security.rsa.RSAPrivateKey.class.getDeclaredConstructors();

                                        for (Constructor ctor : ctors) {
                                            int count = ctor.getParameterCount();
                                            ctor.setAccessible(true);
                                            if (count == 8) {
                                                newPriv = (iaik.security.rsa.RSAPrivateKey)
                                                        ctor.newInstance(
                                                                new BigInteger(privateKey.getModulus().getByteArrayValue()),
                                                                new BigInteger(privateKey.getPublicExponent().getByteArrayValue()),
                                                                new BigInteger(privateKey.getPrivateExponent().getByteArrayValue()),
                                                                new BigInteger(privateKey.getPrime1().getByteArrayValue()),
                                                                new BigInteger(privateKey.getPrime2().getByteArrayValue()),
                                                                new BigInteger(privateKey.getExponent1().getByteArrayValue()),
                                                                new BigInteger(privateKey.getExponent2().getByteArrayValue()),
                                                                new BigInteger(privateKey.getCoefficient().getByteArrayValue()));
                                            }
                                        }
                                        Certificate[] cert = new Certificate[1];
                                        cert[0] = certificate;
                                        System.out.println("Modulus " + newPriv.getModulus());

                                    } catch (Exception ex) {
                                        ex.printStackTrace();
                                    }
                                } else if (object instanceof X509AttributeCertificate) {
                                    try {
                                        byte[] encodedCertificate = ((X509AttributeCertificate) object)
                                                .getValue().getByteArrayValue();
                                        if (x509CertificateFactory == null) {
                                            x509CertificateFactory = CertificateFactory.getInstance("X.509");
                                        }
                                        Certificate certificate = x509CertificateFactory
                                                .generateCertificate(new ByteArrayInputStream(encodedCertificate));

                                    } catch (Exception ex) {

                                    }

                                }
                            }

                            objects = session.findObjects(1);
                        }
                        session.findObjectsFinal();
                    } finally {
                        session.closeSession();
                    }
                }
            } catch (Exception ex) {
                ex.printStackTrace();
        }
    }




    public IAIKPkcs11Private mockPKCS11Module() throws Exception {

        instanceMD = spy(IAIKMD.getInstance());
        PowerMockito.mockStatic(Module.class);
        PKCS11 mod = mock(PKCS11.class);




        manager = Mockito.mock(TokenManager.class);


        // mock neccessary objects
        Token token = PowerMockito.mock(Token.class);
        Session session = PowerMockito.mock(Session.class);
        Slot slot = PowerMockito.mock(Slot.class);
        TokenInfo info = PowerMockito.mock(TokenInfo.class);
        SessionInfo sessionInfo = PowerMockito.mock(SessionInfo.class);
        SlotInfo slotInfo = PowerMockito.mock(SlotInfo.class);
        Slot [] slots = new Slot[1];
        slots[0] = slot;
        Module module = PowerMockito.mock(Module.class);
        Info modInfo = mock
                (Info.class);
        when(modInfo.getLibraryDescription()).thenReturn("I am a private PKCS11 Lib");
        when(module.getInfo()).thenReturn(modInfo);
        when(module.getSlotList(anyBoolean())).thenReturn(slots);
        PowerMockito.when(Module.getInstance(any())).thenReturn(module);
        // initialize slot-info mocking
        byte major = 0x22;
        byte minor = 0x55;
        Version version = PowerMockito.mock(Version.class);
        when(version.getMajor()).thenReturn(major);
        when(version.getMinor()).thenReturn(minor);
        when(slotInfo.getFirmwareVersion()).thenReturn(version);
        when(slotInfo.getSlotDescription()).thenReturn("Iam a special slot");
        when(slotInfo.isTokenPresent()).thenReturn(true);
        // initialize token-info mocking
        when(info.isTokenInitialized()).thenReturn(true);
        when(info.isLoginRequired()).thenReturn(true);
        when(info.getSerialNumber()).thenReturn("34545678");
        // initialize session-info mocking
        when(sessionInfo.getState()).thenReturn(State.RW_PUBLIC_SESSION);
        when(sessionInfo.getDeviceError()).thenReturn(0L);
        when(sessionInfo.isRwSession()).thenReturn(true);
        when(sessionInfo.isSerialSession()).thenReturn(true);
        globalKeyStore = KeyStoreTool.loadAppStore();
        Enumeration<String> aliases = globalKeyStore.aliases();
        Object privobj  = null;
        Object[] objects = new Object[0];
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getKeyEntry(globalKeyStore, alias, "geheim".toCharArray());
            Object[] newObjects = new Object[keys.getSecond().length + 1];
            int index = 0;
            for (; index < (newObjects.length - 1); index++) {
                if (CertificateWizzard.isCertificateSelfSigned(keys.getSecond()[index])) {
                    newObjects[index] = getCertificateObject(keys.getSecond()[index], keys.getSecond()[index]);
                } else {
                    newObjects[index] = getCertificateObject(keys.getSecond()[index], keys.getSecond()[index + 1]);
                }
            }
            privobj = getPrivateKey((iaik.security.rsa.RSAPrivateKey)keys.getFirst());
            newObjects[index] = privobj;
            objects = reallocAndAssign(objects, newObjects);
        }

        doNothing().when(token).initToken("changeit".toCharArray(), "my token");
        when(token.openSession(anyBoolean(), anyBoolean(), any(), any()))
                .thenReturn(session);
        when(token.getSlot()).thenReturn(slot);
        when(token.getTokenInfo()).thenReturn(info);

        when(token.getMechanismList()).thenReturn(new Mechanism[0]);


        // initialize manager mock
        when(manager.getProvider()).thenReturn(provider);
        when(manager.getModule()).thenReturn(module);
        doAnswer(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {
                return "C:\\modole\\mod.dll";
            }
        }).when(manager).getModulePath();
        when(manager.getSession(anyBoolean())).thenReturn(session);
        when(manager.getToken()).thenReturn(token);
        when(manager.login(anyBoolean(), anyString().toCharArray())).thenReturn(true);
        when(manager.loginUser(anyString().toCharArray())).thenReturn(true);
        when(manager.login(any(), anyBoolean(), anyString().toCharArray())).thenReturn(true);
        when(manager.getSlot()).thenReturn(slot);
        when(manager.makeAuthorizedSession(session, "changeit".toCharArray())).thenReturn(true);
        when(manager.makeAuthorizedSession(session, true, "changeit".toCharArray())).thenReturn(true);
        when(manager.makeAuthorizedSession(session, false, "changeit".toCharArray())).thenReturn(true);

        // initialize session mock
        when(session.getToken()).thenReturn(token);
        when(session.getSessionInfo()).thenReturn(sessionInfo);
        OngoingStubbing<Object[]> sessionStub = Mockito.when(session.findObjects(anyInt()));
        sessionStub.thenReturn(objects, new Object[0]);
        Object o = new X509PublicKeyCertificate();
        when(session.createObject(o)).thenReturn(objects[0]);
        o = new RSAPrivateKey();
        when(session.createObject(o)).thenReturn(privobj);
        // here we have to mock encrypt / decrypt and something more

        // initialize slot mocking
        when(slot.getToken()).thenReturn(token);
        when(slot.getModule()).thenReturn(module);
        when(slot.getSlotID()).thenReturn(7676787878L);
        when(slot.getSlotInfo()).thenReturn(slotInfo);
        when(slot.isSetUtf8Encoding()).thenReturn(true);
        Mechanism[] mech = new Mechanism[10];
        mech[0] = Mechanism.RSA_PKCS;

        when(token.getMechanismList()).thenReturn(getMechList());

        Properties props= new Properties();
        props.setProperty("PKCS11_NATIVE_MODULE", "./dummy.dll");
        IAIKPkcs11Private.setUp(manager);
        provider = new IAIKPkcs11Private(manager);
        when(manager.getProvider()).thenReturn(provider);

        Constructor ctor = null;

        Constructor [] ctors = GetInstance.Instance.class.getDeclaredConstructors();
        for (Constructor actual: ctors) {
            if (actual.getParameterCount() == 2) {
                ctor = actual;
                ctor.setAccessible(true);
                break;
            }
        }
        GetInstance.Instance inst = null;




        GetInstance.Instance finalInst = inst;
        //PowerMockito.mockStatic(GetInstance.class);
        //PowerMockito.when(GetInstance.getInstance(service, notNull(Class.class)))
         //       .thenReturn(finalInst);




        return provider;

    }

    private Object getPrivateKey(iaik.security.rsa.RSAPrivateKey key) throws Exception {
        RSAPrivateKey privateKey = new RSAPrivateKey();
        privateKey.putAttribute(Attribute.EXPONENT_1,
                key.getPrimeExponentP().toByteArray());
        privateKey.putAttribute(Attribute.EXPONENT_2,
                key.getPrimeExponentQ().toByteArray());
        privateKey.putAttribute(Attribute.PRIME_1,
                key.getPrimeP().toByteArray());
        privateKey.putAttribute(Attribute.PRIME_2,
                key.getPrimeQ().toByteArray());
        privateKey.putAttribute(Attribute.PRIVATE_EXPONENT,
                key.getPrivateExponent().toByteArray());
        privateKey.putAttribute(Attribute.PUBLIC_EXPONENT,
                key.getPublicExponent().toByteArray());
        privateKey.putAttribute(Attribute.MODULUS,
                key.getModulus().toByteArray());
        privateKey.putAttribute(Attribute.COEFFICIENT,
                key.getCrtCoefficient().toByteArray());
        BigInteger gcd1 = key.getPrimeP().gcd(key.getPrimeExponentP());
        BigInteger gcd2 = key.getPrimeQ().gcd(key.getPrimeExponentQ());
        Constructor[] ctors = iaik.security.rsa.RSAPrivateKey.class.getDeclaredConstructors();

        return privateKey;
    }


    private Object[] getCertificateObjects() throws Exception {
        Object [] array = new Object[0];
        Object [] temp;
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        for (int index = 0; index < keys.getSecond().length; index++) {
            int next = (index + 1);
            if (next < keys.getSecond().length) {
                temp = new Object[array.length + 1];
                Object certObj = getCertificateObject(keys.getSecond()[index], keys.getSecond()[next]);
                for (int i = 0; i < array.length; i++) {
                    temp[i] = array[i];
                }
                array = temp;
                array[index] = certObj;

            }
        }
        return array;
    }
    private Object getCertificateObject(X509Certificate certificate, X509Certificate issuerCert) throws Exception {
        X509PublicKeyCertificate cert = new X509PublicKeyCertificate();
        ByteArrayAttribute issuer = new ByteArrayAttribute(Attribute.ISSUER);
        issuer.setValue(certificate.getIssuerDN().toString().getBytes());
        MessageDigest mdSubj = MessageDigest.getInstance(AlgorithmID.sha1.getJcaStandardName(),
                IAIK.getInstance());
        mdSubj.update(certificate.getPublicKey().getEncoded());
        byte [] hashSubject = mdSubj.digest();
        MessageDigest mdIssuer = MessageDigest.getInstance(AlgorithmID.sha1.getJcaStandardName(),
                IAIK.getInstance());
        mdIssuer.update(issuerCert.getPublicKey().getEncoded());
        byte [] hashIssuer = mdIssuer.digest();
        cert.putAttribute(Attribute.HASH_OF_SUBJECT_PUBLIC_KEY, hashSubject);
        cert.putAttribute(Attribute.HASH_OF_ISSUER_PUBLIC_KEY, hashIssuer);
        cert.putAttribute(Attribute.ISSUER,issuer.getByteArrayValue());
        cert.putAttribute(Attribute.VALUE, certificate.getEncoded());
        return cert;
    }

    private Mechanism[] getMechList() {
        Mechanism [] mechanisms = new Mechanism[26];
        mechanisms[0] = Mechanism.RSA_PKCS_KEY_PAIR_GEN;
        /** @deprecated */
        mechanisms[1] = Mechanism.RSA_PKCS;
        /** @deprecated */
        mechanisms[2] = Mechanism.RSA_9796;
        /** @deprecated */
        mechanisms[3] = Mechanism.RSA_X_509;
        /** @deprecated */
        mechanisms[4] = Mechanism.MD2_RSA_PKCS;
        /** @deprecated */
        mechanisms[5] = Mechanism.MD5_RSA_PKCS;
        /** @deprecated */
        mechanisms[6] = Mechanism.SHA1_RSA_PKCS;
        /** @deprecated */
        mechanisms[7] = Mechanism.RIPEMD128_RSA_PKCS;
        /** @deprecated */
        mechanisms[8] = Mechanism.RIPEMD160_RSA_PKCS;
        /** @deprecated */
        mechanisms[9] = Mechanism.SHA256_RSA_PKCS;
        /** @deprecated */
        mechanisms[10] = Mechanism.SHA384_RSA_PKCS;
        /** @deprecated */
        mechanisms[11] = Mechanism.SHA512_RSA_PKCS;
        /** @deprecated */
        mechanisms[12] = Mechanism.RSA_PKCS_OAEP;
        /** @deprecated */
        mechanisms[13] = Mechanism.RSA_X9_31_KEY_PAIR_GEN;
        /** @deprecated */
        mechanisms[14] = Mechanism.RSA_X9_31;
        /** @deprecated */
        mechanisms[15] = Mechanism.SHA1_RSA_X9_31;
        /** @deprecated */
        mechanisms[16] = Mechanism.RSA_PKCS_PSS;
        /** @deprecated */
        mechanisms[17] = Mechanism.SHA1_RSA_PKCS_PSS;
        /** @deprecated */
        mechanisms[18] = Mechanism.SHA256_RSA_PKCS_PSS;
        /** @deprecated */
        mechanisms[19] = Mechanism.SHA384_RSA_PKCS_PSS;
        /** @deprecated */
        mechanisms[20] = Mechanism.SHA512_RSA_PKCS_PSS;
        /** @deprecated */
        mechanisms[21] = Mechanism.DSA_KEY_PAIR_GEN;
        /** @deprecated */
        mechanisms[22] = Mechanism.DSA;
        /** @deprecated */
        mechanisms[23] = Mechanism.DSA_SHA1;
        /** @deprecated */
        mechanisms[24] = Mechanism.DH_PKCS_KEY_PAIR_GEN;
        /** @deprecated */
        mechanisms[25] = Mechanism.DH_PKCS_DERIVE;
        return mechanisms;
    }

    public static class MyServiceClass extends Provider.Service {
        IAIKPkcs11 provider;
        TokenManager manager;
        TokenKeyStoreSpi keyStoreSpi;

        public MyServiceClass(Provider provider, String type, String algorithm,
                              String className, List<String> aliases,
                              Map<String, String> attributes,
                              TokenManager manager,
                              TokenKeyStoreSpi keyStoreSpi) {
            super(provider, type, algorithm, className, aliases, attributes);
            this.provider = (IAIKPkcs11) provider;
            this.manager = manager;
            this.keyStoreSpi = keyStoreSpi;
        }

        @Override
        public java.lang.Object newInstance(java.lang.Object constructorParameter) throws NoSuchAlgorithmException {
            return keyStoreSpi;
        }
    }

    private Object [] reallocAndAssign(Object[] source, Object[] newData) {
        Object []temporaryObject = new Object[source.length + newData.length];
        int index = 0;
        for (Object object: source) {
            temporaryObject[index] = object;
            index++;
        }
        for (Object object: newData) {
            temporaryObject[index] = object;
            index++;
        }
        return temporaryObject;

    }


}
