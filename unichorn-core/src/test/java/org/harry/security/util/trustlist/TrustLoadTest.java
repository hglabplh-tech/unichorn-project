package org.harry.security.util.trustlist;

import org.etsi.uri._02231.v2_.TrustStatusListType;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

import static org.harry.security.CommonConst.APP_DIR_TRUST;

public class TrustLoadTest {

    @Test
    public void loadDTAGTrustListOK() throws Exception {
        File trustFile = new File(APP_DIR_TRUST, "dtag-corporate-pki.xml");
        InputStream in = new FileInputStream(trustFile);
        TrustStatusListType trustList = TrustListLoader.loadTrust(in);
        TrustListManager manager = new TrustListManager(trustList, false);
    }
}
