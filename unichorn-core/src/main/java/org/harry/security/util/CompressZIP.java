package org.harry.security.util;

import org.apache.commons.compress.archivers.*;
import org.apache.commons.compress.archivers.jar.JarArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.io.IOUtils;

import java.io.*;
import java.util.Date;
import java.util.zip.ZipEntry;

public class CompressZIP {

    public static void compress(File compData, OutputStream fos) throws Exception {


        // Create zip

        String directory = compData.getAbsolutePath().substring(0, compData.getAbsolutePath().lastIndexOf(File.separator));
        Runtime.getRuntime().exec("cmd cd " + directory);
        ArchiveOutputStream aos = new ArchiveStreamFactory().createArchiveOutputStream("zip", fos);
        addToArchiveCompression(compData, aos, "");
        aos.close();
    }
    private static void addToArchiveCompression(File file, ArchiveOutputStream out, String dir) throws IOException {
        String name = dir + File.separator + file.getName();
        if (file.isFile()){
            ZipArchiveEntry entry = new ZipArchiveEntry(name);
            out.putArchiveEntry(entry);
            entry.setSize(file.length());
            IOUtils.copy(new FileInputStream(file), out);
            out.closeArchiveEntry();
        } else if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null){
                for (File child : children){
                    addToArchiveCompression(child, out, name);
                }
            }
        } else {
            System.out.println(file.getName() + " is not supported");
        }
    }
    public static void decompress(File zipFile) throws IOException, ArchiveException {
        // Read zip

        File target = new File(System.getProperty("user.dir"), "temp").getAbsoluteFile();
        target.mkdirs();

        System.out.println("Target is: " + target.getAbsolutePath());
        FileInputStream fis = new FileInputStream(zipFile);
        ArchiveInputStream ais = new ArchiveStreamFactory().createArchiveInputStream("zip", fis);
        ZipArchiveEntry zae = (ZipArchiveEntry) ais.getNextEntry();
        while (zae != null) {

            File curfile = new File(target, zae.getName());
            File parent = curfile.getParentFile().getAbsoluteFile();

            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            if (!zae.isDirectory()) {
                IOUtils.copy(ais, new FileOutputStream(curfile));

            }
            zae = (ZipArchiveEntry) ais.getNextEntry();

        }
        ais.close();

    }
}
