package org.harry.security.util.certandkey;

import com.google.common.io.LineReader;
import iaik.x509.X509Certificate;

import java.io.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Base64;

public class CertWriterReader {

    private X509Certificate certificate;

    private final static String HEADER = "-----BEGIN CERTIFICATE-----";

    private final static String FOOTER = "-----END CERTIFICATE-----";

    public CertWriterReader(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public CertWriterReader() {

    }

    public void writeToFilePEM(OutputStream stream) throws CertificateEncodingException, IOException {
        byte [] outArray = Base64.getEncoder().encode(certificate.getEncoded());
        ByteArrayInputStream in = new ByteArrayInputStream(outArray);
        byte buffer[] = new byte[65];
        String begin = HEADER + '\n';
        stream.write(begin.getBytes());
        int read = in.read(buffer,0,64);
        while(read > 0) {
            buffer[read] = '\n';
            stream.write(buffer, 0, (read + 1));
            read = in.read(buffer,0,64);
        }
        String end = FOOTER + '\n';
        stream.write(end.getBytes());
        stream.close();
        in.close();
    }

    public void writeX509(OutputStream stream) throws IOException {
        this.certificate.writeTo(stream);
        stream.close();
    }

    public X509Certificate readX509(InputStream stream) throws IOException, CertificateException {
        X509Certificate cert = new X509Certificate(stream);
        return cert;
    }

    public X509Certificate readFromFilePEM(InputStream stream) throws CertificateException, IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Readable readable = new InputStreamReader(stream);
        LineReader in = new LineReader(readable);
        String line = in.readLine();
        byte [] buffer = new byte[64];
        if (line.equals(HEADER)) {
            String row = in.readLine();
            while (row != null && !row.isEmpty()) {
                if (!row.equals(FOOTER)) {
                    buffer = row.getBytes();
                    out.write(buffer, 0, row.length());
                }
                row = in.readLine();
            }
        }
        byte [] converted = Base64.getDecoder().decode(out.toByteArray());
        X509Certificate result = new X509Certificate(converted);
        return result;
    }


    public static enum CertType {
        PEM,
        X509,
        P12;
    }

}
