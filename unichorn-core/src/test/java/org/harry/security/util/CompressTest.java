package org.harry.security.util;

import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import static org.harry.security.CommonConst.APP_DIR;
import static org.harry.security.CommonConst.APP_DIR_TRUST;

public class CompressTest {

    @Test
    public void compressOK() throws Exception {
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
