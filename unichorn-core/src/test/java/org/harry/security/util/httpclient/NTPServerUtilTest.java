package org.harry.security.util.httpclient;

import org.junit.Test;

public class NTPServerUtilTest {

    @Test
    public void testNTPOK() {
        NTPServerUtil.getNTPTime();
    }
}
