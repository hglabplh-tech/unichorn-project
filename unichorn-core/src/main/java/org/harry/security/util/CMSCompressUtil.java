package org.harry.security.util;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSAlgorithmID;
import iaik.cms.CMSException;
import iaik.cms.CompressedDataStream;
import iaik.cms.ContentInfoStream;
import org.apache.commons.io.IOUtils;
import org.harry.security.util.bean.SigningBean;

import javax.activation.DataSource;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;

public class CMSCompressUtil {

    /**
     * Creates a CMS <code>CompressedData</code> object.
     * <p>
     * @param signingBean the bean holding the data and parameters to compress
     *
     * @return the BER encoding of the <code>CompressedData</code> object just created as data-source
     *
     * @exception CMSException if the <code>CompressedData</code> object cannot
     *                          be created
     * @exception IOException if an I/O error occurs
     * @exception NoSuchAlgorithmException if the compression algorithm is not supported
     */
    public static DataSource compressDataStreamCMS(SigningBean signingBean)
            throws CMSException, IOException, NoSuchAlgorithmException {

        System.out.println("Create a new CompressedData message.");

        // create a new CompressedData object
        CompressedDataStream compressedData = new CompressedDataStream(signingBean.getDataIN(),
                (AlgorithmID) CMSAlgorithmID.zlib_compress.clone(),
                CompressedDataStream.IMPLICIT);


        // for testing return the CompressedData as BER encoded byte array with block size of 4
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        compressedData.setBlockSize(4);
        ContentInfoStream cis = new ContentInfoStream(compressedData);
        cis.writeTo(os);
        ByteArrayInputStream input = new ByteArrayInputStream(os.toByteArray());
        SigningUtil.InputStreamDataSource ds = new SigningUtil.InputStreamDataSource(input);
        return ds;
    }

    /**
     * Parses a CMS <code>CompressedData</code> object.
     *
     * @param signingBean  the bean containing all the values neccessary for compression
     *
     * @return the decompressed message as data-source
     *
     * @exception CMSException if the CompressedData cannot be parsed
     * @exception IOException if an I/O error occurs
     * @exception NoSuchAlgorithmException if the compression algorithm is not supported
     */
    public static DataSource decompressDataStreamCMS(SigningBean signingBean)
            throws CMSException, IOException, NoSuchAlgorithmException {

        // create the CompressedData object
        CompressedDataStream compressedData = new CompressedDataStream(signingBean.getDataIN());

        // get an InputStream for reading and decompressing the content
        InputStream data = compressedData.getInputStream();
        SigningUtil.InputStreamDataSource ds = new SigningUtil.InputStreamDataSource(data);
        return ds;
    }


}
