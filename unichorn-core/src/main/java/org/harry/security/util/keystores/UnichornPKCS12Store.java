package org.harry.security.util.keystores;

import iaik.asn1.ASN1Object;
import iaik.asn1.structures.AlgorithmID;
import iaik.pkcs.PKCSException;
import iaik.pkcs.pkcs12.CertificateBag;
import iaik.pkcs.pkcs12.KeyBag;
import iaik.pkcs.pkcs12.PKCS12;
import iaik.pkcs.pkcs8.EncryptedPrivateKeyInfo;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.SubjectKeyIdentifier;
import org.harry.security.util.Tuple;
import org.harry.security.util.algoritms.CryptoAlg;
import org.pmw.tinylog.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

public class UnichornPKCS12Store extends KeyStoreSpi  {

    private PKCS12 pkcs12StoreObject = null;

    private KeyBag[] keyBags = null;

    private CertificateBag[] certBags = null;

    private Map<String, Tuple<KeyBag, Tuple<String,X509Certificate>[]>> privKeyEntries = new HashMap<>();

    private Map<String, X509Certificate> realCertMap = new HashMap<>();

    private Set<String> aliases = new HashSet<>();

    private AlgorithmID authSafesAlg = CryptoAlg.PBE_SHAA_40BITSRC2_CBC.getAlgId();

    private AlgorithmID shroudedKeyBagAlg = CryptoAlg.PBE_SHAA_40BITSRC2_CBC.getAlgId();


    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        Tuple<KeyBag, Tuple<String,X509Certificate>[]> entry = privKeyEntries.get(alias);
        KeyBag bag = entry.getFirst();
        Key key = bag.getPrivateKey();
        return key;
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        Tuple<KeyBag, Tuple<String,X509Certificate>[]> entry = privKeyEntries.get(alias);
        Tuple<String,X509Certificate>[]  certArray = entry.getSecond();
        X509Certificate[] chain = new X509Certificate[certArray.length];
        for (int index = 0; index < chain.length; index++) {
            chain[index] = certArray[index].getSecond();
        }
        return chain;
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        Tuple<KeyBag, Tuple<String,X509Certificate>[]> entry = privKeyEntries.get(alias);
        if (entry != null) {
            Tuple<String, X509Certificate>[] certArray = entry.getSecond();
            X509Certificate[] chain = new X509Certificate[certArray.length];
            for (int index = 0; index < chain.length; index++) {
                chain[index] = certArray[index].getSecond();
            }
            return chain[0];
        } else {
            X509Certificate cert = realCertMap.get(alias);
            return cert;
        }
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        return null;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        try {
            Tuple[] newTupleArray = new Tuple[chain.length];
            newTupleArray[0] = new Tuple(alias, chain[0]);
            for (int index = 1; index < newTupleArray.length; index++) {
                newTupleArray[index] = new Tuple(null, chain[index]);
            }
            byte[] keyId = ((SubjectKeyIdentifier) Util.convertCertificate(chain[0])
                    .getExtension(SubjectKeyIdentifier.oid)).get();
            KeyBag keyBag = new KeyBag((PrivateKey) key, alias, keyId);
            privKeyEntries.put(alias, new Tuple(keyBag, newTupleArray));
        } catch (Exception ex) {
            throw new IllegalStateException("error during stKey: " + ex.getMessage(), ex);
        }
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        try {
            Tuple[] newTupleArray = new Tuple[chain.length];
            newTupleArray[0] = new Tuple(alias, chain[0]);
            for (int index = 1; index < newTupleArray.length; index++) {
                newTupleArray[index] = new Tuple(null, chain[index]);
            }
            EncryptedPrivateKeyInfo keyInfo = new EncryptedPrivateKeyInfo(key);
            ASN1Object asn1Key = keyInfo.toASN1Object();
            KeyBag keyBag = new KeyBag(null);
            keyBag.decode(asn1Key);
            keyBag.setFriendlyName(alias);
            byte [] array = alias.getBytes();
            keyBag.setLocalKeyID(array);
            privKeyEntries.put(alias, new Tuple(keyBag, newTupleArray));
        } catch (Exception ex) {

        }
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        try {
            realCertMap.put(alias, Util.convertCertificate(cert));
        } catch(Exception ex) {
            throw new KeyStoreException(ex.getMessage());
        }
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        boolean removed = false;
        Tuple<KeyBag, Tuple<String,X509Certificate>[]> entry = privKeyEntries.get(alias);
        if (entry != null) {
            privKeyEntries.remove(alias);
            removed = true;
        }
        X509Certificate entryCert = realCertMap.get(alias);
        if (entryCert != null) {
            realCertMap.remove(alias);
            removed = true;
        }

        if ( !removed) {
            throw new KeyStoreException("unable to remove: " + alias);
        }
    }

    @Override
    public Enumeration<String> engineAliases() {

        Enumeration<String> result = new Enumeration<String>() {

            private Iterator<String> it = aliases.iterator();
            @Override
            public boolean hasMoreElements() {
                return it.hasNext();
            }

            @Override
            public String nextElement() {
                return it.next();
            }
        };
        return result;
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return aliases.contains(alias);
    }

    @Override
    public int engineSize() {
        return aliases.size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return (privKeyEntries.get(alias) != null);
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        return (realCertMap.get(alias) != null);
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        try {
            X509Certificate certificate = Util.convertCertificate(cert);
            Optional<Tuple<KeyBag, Tuple<String, X509Certificate>[]>> value =
                    privKeyEntries.values().stream().filter(e ->
                    {
                        return e.getSecond()[0].getSecond().getSerialNumber().equals(certificate.getSerialNumber());
                    })
                            .findFirst();
            if (value.isPresent()) {
                return value.get().getSecond()[0].getFirst();
            } else {
                Optional<Map.Entry<String, X509Certificate>> entryOpt = realCertMap.entrySet()
                        .stream()
                        .filter(e -> e.getValue().getSerialNumber().equals(certificate.getSerialNumber()))
                        .findFirst();
                return entryOpt.map(Map.Entry::getKey).orElse(null);
            }
        } catch (Exception ex) {
            throw new IllegalStateException(" cannot proceed find alias by cert", ex);
        }
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        try {
            collectTheBagsToStore();
            PKCS12 pkcs12Store = new PKCS12(keyBags, certBags, true);
            pkcs12Store.encrypt(password, authSafesAlg,
                    shroudedKeyBagAlg);
            pkcs12Store.toASN1Object();
            pkcs12Store.writeTo(stream);
            stream.flush();
            stream.close();
        } catch (PKCSException ex) {
            throw new CertificateException(ex.toString());
        }
    }

    public void engineStore(KeyStore.LoadStoreParameter storeParam) throws IOException, NoSuchAlgorithmException, CertificateException {
        if (storeParam == null) {
            throw new IOException("store param not given");
        }
        if (!(storeParam instanceof UP12StoreParams)) {
            throw new IOException("store param not accepted");
        }
        try {
            KeyStore.ProtectionParameter parameter = storeParam.getProtectionParameter();
            if (parameter instanceof KeyStore.PasswordProtection) {
                KeyStore.PasswordProtection passwdProt = (KeyStore.PasswordProtection) parameter;
                char[] passwd = passwdProt.getPassword();
                authSafesAlg = ((UP12StoreParams) storeParam).getAuthSafesAlg();
                shroudedKeyBagAlg = ((UP12StoreParams) storeParam).getShroudedKeyBagAlg();
                engineStore(((UP12StoreParams) storeParam).getOutputStream(), passwd);
                passwdProt.destroy();
            } else {
                throw new NoSuchAlgorithmException("protection cannot be handled: "
                        + parameter.getClass().getCanonicalName());
            }
        } catch (Exception ex) {
            Logger.trace("error storing: " + ex.getMessage());
            Logger.trace(ex);
            throw new IOException("store cannot be stored");
        }
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        try {
            if (stream != null) {
                this.pkcs12StoreObject = new PKCS12(stream);
                this.pkcs12StoreObject.verify(password);
                this.pkcs12StoreObject.decrypt(password);
                keyBags = pkcs12StoreObject.getKeyBags();
                certBags = pkcs12StoreObject.getCertificateBags();
                collectKeyEntries();
                collectCertEntries();
                Logger.trace("loaded");
            }
        } catch (Exception ex) {
            Logger.trace("error occurred loading PKCS12 store" + ex.getMessage());
            Logger.trace(ex);
            throw new IllegalStateException("error occurred loading PKCS12 store", ex);
        }
    }

    public void collectKeyEntries() {
        for (KeyBag keyBag: keyBags) {
            String alias = keyBag.getFriendlyName();
            Optional<CertificateBag> certBag = Optional.empty();
            X509Certificate [] chain = new X509Certificate[0];
            boolean found = false;
            for (CertificateBag e : certBags) {
                System.out.println("test: " + e.getFriendlyName());
                if (alias.equals(e.getFriendlyName())) {
                    System.out.println("found: " + e.getFriendlyName());
                    chain = allocChain(chain, e.getCertificate());
                    found = true;
                } else if (e.getFriendlyName() == null && found) {
                    chain = allocChain(chain, e.getCertificate());
                } else if (found) {
                    break;
                }
            }
            if (chain.length > 0) {
                Logger.trace(chain[0].toString(true));
                int index = 0;
                Tuple[] newTupleArray = new Tuple[chain.length];
                for (X509Certificate cert: chain) {
                    Tuple<String, X509Certificate> newTuple;
                    if (index == 0) {
                        newTuple = new Tuple<String, X509Certificate>(keyBag.getFriendlyName(), chain[index]) ;
                    } else {
                        newTuple = new Tuple<String, X509Certificate>(null, chain[index]) ;
                    }
                    newTupleArray[index] = newTuple;
                    index++;
                }
                this.privKeyEntries.put(keyBag.getFriendlyName(), new Tuple(keyBag, newTupleArray));
                this.aliases.add(keyBag.getFriendlyName());
            }
        }
    }

    public void collectCertEntries() {
        for (CertificateBag e : certBags) {
            if (e.getFriendlyName() != null && privKeyEntries.get(e.getFriendlyName()) == null) {
                this.realCertMap.put(e.getFriendlyName(), e.getCertificate());
                this.aliases.add(e.getFriendlyName());
            }
        }
    }

    public X509Certificate[] allocChain (X509Certificate[] chain, X509Certificate toAdd) {
        X509Certificate[] temp = new X509Certificate[chain.length + 1];
        int index = 0;
        for (;index < chain.length; index++) {
            temp[index] = chain[index];
        }
        temp[index] = toAdd;
        return temp;
    }

    public void collectTheBagsToStore()  {
        try {
            List<CertificateBag> result = new ArrayList<>();
            for (Map.Entry<String, X509Certificate> entry : realCertMap.entrySet()) {
                byte[] keyId = ((SubjectKeyIdentifier) entry.getValue()
                        .getExtension(SubjectKeyIdentifier.oid)).get();
                CertificateBag newBag = new CertificateBag(entry.getValue(), entry.getKey(), keyId);
                result.add(newBag);
            }
            for (Map.Entry<String, Tuple<KeyBag, Tuple<String, X509Certificate>[]>> entry : privKeyEntries.entrySet()) {
                for (Tuple<String, X509Certificate> certEntry : entry.getValue().getSecond()) {
                    byte[] keyId = ((SubjectKeyIdentifier) certEntry.getSecond()
                            .getExtension(SubjectKeyIdentifier.oid)).get();
                    CertificateBag newBag = new CertificateBag(certEntry.getSecond(), certEntry.getFirst(), keyId);
                    result.add(newBag);
                }
            }
            certBags = new CertificateBag[result.size()];
            for (int index = 0; index < certBags.length; index++) {
                certBags[index] = result.get(index);
            }
            Collection<Tuple<KeyBag, Tuple<String, X509Certificate>[]>> keyCollection = privKeyEntries.values();
            keyBags = new KeyBag[keyCollection.size()];
            AtomicInteger index = new AtomicInteger();
            keyCollection.forEach(e -> {
                keyBags[index.getAndIncrement()] =
                        e.getFirst();
            });
        } catch (Exception ex) {
            Logger.trace("error during collect" + ex.getMessage());
            Logger.trace(ex);
            throw new IllegalStateException("error during collect", ex);
        }

    }
}
