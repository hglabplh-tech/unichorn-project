package org.harry.security.util.algoritms;

public interface DigestMethod {
    // All methods can be found in RFC 6931.

    /**
     * The <a href="http://www.w3.org/2000/09/xmldsig#sha1">
     * SHA1</a> digest method algorithm URI.
     */
    String SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";

    /**
     * The <a href="http://www.w3.org/2001/04/xmldsig-more#sha224">
     * SHA224</a> digest method algorithm URI.
     *
     * @since 11
     */
    String SHA224 = "http://www.w3.org/2001/04/xmldsig-more#sha224";

    /**
     * The <a href="http://www.w3.org/2001/04/xmlenc#sha256">
     * SHA256</a> digest method algorithm URI.
     */
    String SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

    /**
     * The <a href="http://www.w3.org/2001/04/xmldsig-more#sha384">
     * SHA384</a> digest method algorithm URI.
     *
     * @since 11
     */
    String SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";

    /**
     * The <a href="http://www.w3.org/2001/04/xmlenc#sha512">
     * SHA512</a> digest method algorithm URI.
     */
    String SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";

    /**
     * The <a href="http://www.w3.org/2001/04/xmlenc#ripemd160">
     * RIPEMD-160</a> digest method algorithm URI.
     */
    String RIPEMD160 = "http://www.w3.org/2001/04/xmlenc#ripemd160";

    /**
     * The <a href="http://www.w3.org/2007/05/xmldsig-more#sha3-224">
     * SHA3-224</a> digest method algorithm URI.
     *
     * @since 11
     */
    String SHA3_224 = "http://www.w3.org/2007/05/xmldsig-more#sha3-224";

    /**
     * The <a href="http://www.w3.org/2007/05/xmldsig-more#sha3-256">
     * SHA3-256</a> digest method algorithm URI.
     *
     * @since 11
     */
    String SHA3_256 = "http://www.w3.org/2007/05/xmldsig-more#sha3-256";

    /**
     * The <a href="http://www.w3.org/2007/05/xmldsig-more#sha3-384">
     * SHA3-384</a> digest method algorithm URI.
     *
     * @since 11
     */
    String SHA3_384 = "http://www.w3.org/2007/05/xmldsig-more#sha3-384";

    /**
     * The <a href="http://www.w3.org/2007/05/xmldsig-more#sha3-512">
     * SHA3-512</a> digest method algorithm URI.
     *
     * @since 11
     */
    String SHA3_512 = "http://www.w3.org/2007/05/xmldsig-more#sha3-512";

}
