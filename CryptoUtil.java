import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.zip.CRC32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CryptoUtil {

    private static final Logger logger = LoggerFactory.getLogger(CryptoUtil.class);

    private static final String MD5 = "MD5";
    private static final String SHA256 = "SHA-256";
    private static final String HMAC_SHA = "HMAC-SHA1";

    private static String byteArrayToString(byte[] digest) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < digest.length; i++) {
            String shaHex = Integer.toHexString(digest[i] & 0xFF);
            if (shaHex.length() < 2) {
                hexString.append(0);
            }
            hexString.append(shaHex);
        }
        return hexString.toString();
    }

    public static String doMD5(String sign) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(MD5);
            byte[] digest = messageDigest.digest(sign.getBytes("utf-8"));
            String digestStr = byteArrayToString(digest);
            logger.debug("msg:{}.md5 result:{}", sign, digestStr);
            return digestStr;
        } catch (Throwable e) {
            logger.error("execute md5 failed, exception:{}", e);
            return "";
        }
    }

    public static String doSHA256(String sign) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(SHA256);
            byte[] digest = messageDigest.digest(sign.getBytes());
            String digestStr = byteArrayToString(digest);
            logger.debug("msg:{}.sha256 result:{}", sign, digestStr);
            return digestStr;
        } catch (Throwable e) {
            logger.error("execute sha256 failed, exception:{}", e);
            return "";
        }
    }

    // HmacSHA1加密数据，结果转为BASE64形式
    public static String doHmacSHA1Base64(String data, String key) {
        try {
            byte[] keyBytes = key.getBytes();
            SecretKeySpec signingKey = new SecretKeySpec(keyBytes, "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(signingKey);
            byte[] rawHmac = mac.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(rawHmac);
        } catch (InvalidKeyException e) {
            logger.error("execute HmacSHA1Base64 failed, exception:{}", e);
            return "";
        } catch (NoSuchAlgorithmException e) {
            logger.error("execute HmacSHA1Base64 failed, exception:{}", e);
            return "";
        } catch (IllegalStateException e) {
            logger.error("execute HmacSHA1Base64 failed, exception:{}", e);
            return "";
        }
    }

    public static long doCrc32(String data) {
        CRC32 crc = new CRC32();
        crc.update(data.getBytes());
        return crc.getValue();
    }
}
