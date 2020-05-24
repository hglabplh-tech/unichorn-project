package org.harry.security.util;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.harry.security.CommonConst.APP_DIR;
import static org.harry.security.CommonConst.APP_DIR_TRUST;

import static org.hamcrest.CoreMatchers.is;

public class CompressTest {

    @Test
    public void compressOKFile() throws Exception {
        File out = File.createTempFile("data", ".zip");
        File input = new File(APP_DIR_TRUST, "TL-DE.xml");
        CompressZIP.compress(input, new FileOutputStream(out));
        FileInputStream zip = new FileInputStream(out);
        CompressZIP.decompress(out);
        File output = new File(System.getProperty("user.dir") + "\\temp", "TL-DE.xml");
        assertThat(output.exists(), is(true));
        compareFiles(input, output);
    }

    private void compareFiles(File input, File output) throws IOException {
        byte [] inbytes = IOUtils.toByteArray(new FileInputStream(input));
        byte [] outbytes = IOUtils.toByteArray(new FileInputStream(output));
        assertThat(Arrays.equals(inbytes, outbytes), is(true));
    }

    @Test
    public void compressOKDirectory() throws Exception {
        File out = File.createTempFile("data", ".zip");
        File input = new File(APP_DIR_TRUST);
        CompressZIP.compress(input, new FileOutputStream(out));
        FileInputStream zip = new FileInputStream(out);
        CompressZIP.decompress(out);
    }
    @Test
    public void compressOKWithSubDir() throws Exception {
        File out = File.createTempFile("data", ".zip");
        File input = new File(APP_DIR);
        CompressZIP.compress(input, new FileOutputStream(out));
        FileInputStream zip = new FileInputStream(out);
        CompressZIP.decompress(out);
    }

    @Test
    public void compressJarOK() throws Exception {
        File out = File.createTempFile("data", ".zip");
        File input = new File(APP_DIR_TRUST);
        CompressZIP.compress(input, new FileOutputStream(out));
        FileInputStream zip = new FileInputStream(out);
        CompressZIP.decompress(out);
    }
    @Test
    public void compressJarOKWithSubDir() throws Exception {
        File out = File.createTempFile("data", ".jar");
        File input = new File(APP_DIR);
        CompressJAR.compress(input, new FileOutputStream(out));
        FileInputStream zip = new FileInputStream(out);
        CompressJAR.decompress(out);
    }
    @Test
    public void compressTarOKWithSubDir() throws Exception {
        File out = File.createTempFile("data", ".tar");
        File input = new File(APP_DIR);
        CompressTAR.compress(input, new FileOutputStream(out));
        FileInputStream zip = new FileInputStream(out);
        CompressTAR.decompress(out);
    }


}
