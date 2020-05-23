package harry.security.responder.resources;

import org.apache.commons.io.IOUtils;
import org.pmw.tinylog.Logger;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;

public class TokenThread implements Runnable {
    private final File tokFile;
    private final byte [] token;
    public TokenThread(File tokFile, String token) {
        this.tokFile = tokFile;
        this.token = token.getBytes();
    }
    @Override
    public void run() {
        try {
            ByteArrayInputStream tokIN = new ByteArrayInputStream(token);
            OutputStream out = new FileOutputStream(tokFile);
            Logger.trace("create token file");
            IOUtils.copy(tokIN, out);
            out.flush();
            out.close();
            tokIN.close();
            Thread.sleep(1000 * 60 * 5);
            Logger.trace("delete token file");
            tokFile.delete();
        } catch  (Exception ex) {
            throw new IllegalStateException("Token I/O failed", ex);
        }
    }
}
