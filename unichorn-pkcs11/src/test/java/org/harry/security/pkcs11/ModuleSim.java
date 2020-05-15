package org.harry.security.pkcs11;

import iaik.asn1.structures.AlgorithmID;
import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.objects.*;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.TokenKeyStore;
import iaik.pkcs.pkcs11.provider.TokenKeyStoreSpi;
import iaik.pkcs.pkcs11.provider.TokenManager;
import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import iaik.security.provider.IAIK;
import iaik.security.provider.IAIKMD;
import iaik.x509.X509Certificate;
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
@PrepareForTest(fullyQualifiedNames = {"iaik.pkcs.pkcs11.Module", "sun.security.jca.GetInstance" })
public class ModuleSim {

    IAIKMD instanceMD = null;
    Certificate certificate;
    @Test
    public void testSlotList() throws Exception {
        IAIKPkcs11 provider = mockPKCS11Module();
        Security.insertProviderAt(instanceMD, 1);
        Security.insertProviderAt(IAIK.getInstance(), 2);





        Module pkcs11Module = Module.getInstance("blubber");

        KeyStore keyStore = TokenKeyStore.getInstance(TokenKeyStore.KEYSTORE_TYPE);
        keyStore.load(null, "changeit".toCharArray());


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

                        CertificateFactory x509CertificateFactory = null;
                        for (int index =0;index < objects.length; index++) {
                            Object object = objects[index];

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
                                        keyStore.setCertificateEntry("cert", certificate);
                                        X509Certificate iaik = new X509Certificate(certificate.getEncoded());
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

                                        for (Constructor ctor:ctors) {
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
                                        if (certificate != null && newPriv != null) {
                                            keyStore.setKeyEntry("keyentry",
                                                    newPriv,
                                                    "changeit".toCharArray(),
                                                    cert);
                                        }
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
                            // test the (deep) cloning feature
                            // Object clonedObject = (Object) object.clone();


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




    public IAIKPkcs11 mockPKCS11Module() throws Exception {

        instanceMD = spy(IAIKMD.getInstance());
        PowerMockito.mockStatic(Module.class);
        PKCS11 mod = mock(PKCS11.class);
        Module module = PowerMockito.mock(Module.class);
        PowerMockito.when(Module.getInstance(any())).thenReturn(module);



        TokenManager manager = Mockito.mock(TokenManager.class);

        Properties props= new Properties();
        props.setProperty("PKCS11_NATIVE_MODULE", "./dummy.dll");
        IAIKPkcs11 provider = Mockito.mock(IAIKPkcs11.class);

        // mock neccessary objects
        Token token = PowerMockito.mock(Token.class);
        Session session = PowerMockito.mock(Session.class);
        Slot slot = PowerMockito.mock(Slot.class);
        TokenInfo info = PowerMockito.mock(TokenInfo.class);
        SessionInfo sessionInfo = PowerMockito.mock(SessionInfo.class);
        SlotInfo slotInfo = PowerMockito.mock(SlotInfo.class);
        Slot [] slots = new Slot[1];
        slots[0] = slot;

        // initialize slot-info mocking
        byte major = 0x22;
        byte minor = 0x55;
        Version version = PowerMockito.mock(Version.class);
        when(version.getMajor()).thenReturn(major);
        when(version.getMinor()).thenReturn(minor);
        when(slotInfo.getFirmwareVersion()).thenReturn(version);
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
        // initialize token mocking
        Object privobj = getPrivateKey();
        Object obj = getCertificateObjects();
        Object [] objects = new Object[2];
        objects[0] = obj;
        objects[1] = privobj;
        doNothing().when(token).initToken("changeit".toCharArray(), "my token");


        when(token.openSession(anyBoolean(), anyBoolean(), any(), any()))
                .thenReturn(session);
        when(token.getSlot()).thenReturn(slot);
        when(token.getTokenInfo()).thenReturn(info);

        when(token.getMechanismList()).thenReturn(new Mechanism[0]);
        when(module.getSlotList(anyBoolean())).thenReturn(slots);

        // initialize manager mock
        when(manager.getProvider()).thenReturn(provider);
        when(manager.getModule()).thenReturn(module);
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
        sessionStub.thenReturn(objects);
        Object o = new X509PublicKeyCertificate();
        when(session.createObject(o)).thenReturn(obj);
        o = new RSAPrivateKey();
        when(session.createObject(o)).thenReturn(privobj);
        // here we have to mock encrypt / decrypt and something more

        // initialize slot mocking
        when(slot.getToken()).thenReturn(token);
        when(slot.getModule()).thenReturn(module);
        when(slot.getSlotID()).thenReturn(7676787878L);
        when(slot.getSlotInfo()).thenReturn(slotInfo);
        when(slot.isSetUtf8Encoding()).thenReturn(true);


        when(provider.getTokenManager()).thenReturn(manager);
        when(provider.getName()).thenAnswer(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {
                return IAIKPkcs11.PROVIDER_BASE_NAME;
            }
        });


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
        TokenKeyStoreSpi keyStoreSpi = new TokenKeyStoreSpi(manager);
        TokenKeyStore keyStore = new TokenKeyStore(keyStoreSpi, provider,
                TokenKeyStore.KEYSTORE_TYPE);

        Provider.Service service = new MyServiceClass(provider,
                "KeyStore",
                TokenKeyStore.KEYSTORE_TYPE,
                TokenKeyStore.class.getName(),
                Collections.<String>emptyList(),
                Collections.emptyMap(),
                manager, keyStoreSpi);
        try {
            inst =
                    (GetInstance.Instance)ctor.newInstance(service.getProvider(), keyStore);
        } catch (InstantiationException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        }

        doAnswer(new Answer<Provider.Service>() {
            @Override
            public Provider.Service answer(InvocationOnMock invocation) throws Throwable {
                return service;
            }
        }).when(instanceMD).getService("KeyStore","PKCS11KeyStore");


        GetInstance.Instance finalInst = inst;
        //PowerMockito.mockStatic(GetInstance.class);
        //PowerMockito.when(GetInstance.getInstance(service, notNull(Class.class)))
         //       .thenReturn(finalInst);




        return provider;

    }

    private Object getPrivateKey() throws Exception {
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        iaik.security.rsa.RSAPrivateKey key =
                (iaik.security.rsa.RSAPrivateKey)keys.getFirst();
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


    private Object getCertificateObjects() throws Exception {
        KeyStore store = KeyStoreTool.loadAppStore();
        Tuple<PrivateKey, X509Certificate[]> keys = KeyStoreTool.getAppKeyEntry(store);
        X509PublicKeyCertificate cert = new X509PublicKeyCertificate();
        ByteArrayAttribute issuer = new ByteArrayAttribute(Attribute.ISSUER);
        issuer.setValue(keys.getSecond()[0].getIssuerDN().toString().getBytes());
        MessageDigest mdSubj = MessageDigest.getInstance(AlgorithmID.sha1.getJcaStandardName(),
                IAIK.getInstance());
        mdSubj.update(keys.getSecond()[0].getPublicKey().getEncoded());
        byte [] hashSubject = mdSubj.digest();
        MessageDigest mdIssuer = MessageDigest.getInstance(AlgorithmID.sha1.getJcaStandardName(),
                IAIK.getInstance());
        mdIssuer.update(keys.getSecond()[1].getPublicKey().getEncoded());
        byte [] hashIssuer = mdIssuer.digest();
        cert.putAttribute(Attribute.HASH_OF_SUBJECT_PUBLIC_KEY, hashSubject);
        cert.putAttribute(Attribute.HASH_OF_ISSUER_PUBLIC_KEY, hashIssuer);
        cert.putAttribute(Attribute.ISSUER,issuer.getByteArrayValue());
        cert.putAttribute(Attribute.VALUE, keys.getSecond()[0].getEncoded());
        return cert;
    }

    public static class MyServiceClass extends Provider.Service {
        IAIKPkcs11 provider;
        TokenManager manager;
        TokenKeyStoreSpi keyStoreSpi;
        public  MyServiceClass(Provider provider, String type, String algorithm,
                       String className, List<String> aliases,
                       Map<String,String> attributes,
                               TokenManager manager,
                               TokenKeyStoreSpi keyStoreSpi) {
            super(provider, type, algorithm, className, aliases, attributes);
            this.provider = (IAIKPkcs11)provider;
            this.manager = manager;
            this.keyStoreSpi = keyStoreSpi;
        }

        @Override
        public java.lang.Object newInstance(java.lang.Object constructorParameter) throws NoSuchAlgorithmException {
            return keyStoreSpi;
        }
    }

}
