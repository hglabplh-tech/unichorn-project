package org.harry.security.util;

import org.apache.commons.compress.archivers.ArchiveException;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.ArchiveOutputStream;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;
import org.apache.commons.compress.archivers.jar.JarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.io.IOUtils;

import java.io.*;

public class
CompressTAR {

    /**
     *
     * @param compData the data to compress either file or directory
     * @param fos the output stream for the result of compression
     * @throws Exception error case
     */
    public static void compress(File compData, OutputStream fos) throws Exception {


        // Create zip

        String directory = compData.getAbsolutePath().substring(0, compData.getAbsolutePath().lastIndexOf(File.separator));
        Runtime.getRuntime().exec("cmd cd " + directory);
        TarArchiveOutputStream aos = (TarArchiveOutputStream) new ArchiveStreamFactory().createArchiveOutputStream("tar", fos);
        aos.setBigNumberMode(TarArchiveOutputStream.BIGNUMBER_STAR);
        aos.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);
        addToArchiveCompression(compData, aos, "");
        aos.close();
    }
    private static void addToArchiveCompression(File file, ArchiveOutputStream out, String dir) throws IOException {
        String name = dir + File.separator + file.getName();

        if (file.isFile()){
            TarArchiveEntry entry = new TarArchiveEntry(file);
            out.putArchiveEntry(entry);
            BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file));
            IOUtils.copy(bis, out);
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

    /**
     * read the ZIP file and decompress the files
     * @param tarFile the TAR file
     * @throws IOException error case
     * @throws ArchiveException error case
     */
    public static void decompress(File tarFile) throws IOException, ArchiveException {
        // Read zip

        File target = new File(System.getProperty("user.dir"), "tempTAR").getAbsoluteFile();
        target.mkdirs();

        System.out.println("Target is: " + target.getAbsolutePath());
        FileInputStream fis = new FileInputStream(tarFile);
        ArchiveInputStream ais = new ArchiveStreamFactory().createArchiveInputStream("tar", fis);
        TarArchiveEntry zae = (TarArchiveEntry) ais.getNextEntry();
        while (zae != null) {

            File curfile = new File(target, zae.getName());
            File parent = curfile.getParentFile().getAbsoluteFile();

            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            if (!zae.isDirectory()) {
                IOUtils.copy(ais, new FileOutputStream(curfile));

            }
            zae = (TarArchiveEntry) ais.getNextEntry();

        }
        ais.close();

    }
}
