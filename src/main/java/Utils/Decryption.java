package Utils;

import Algorithm.AESUtil;
import Algorithm.RSAUtil;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;

public class Decryption {
    //AES解密
    public static String aes_decryption(String encodedText, SecretKey key) throws IOException {
        byte[] encodedBytes = AESUtil.base642Byte(encodedText);
        String message = AESUtil.AesCbcDecode(encodedBytes, key, AESUtil.IVPARAMETERS);

        return message;
    }

    //RSA解密，传入密文和私钥，得到明文
    public static BigInteger rsa_decryption(BigInteger privateText, PrivateKey privateKey) throws Exception {
//        byte[] privateTextByte = RSAUtil.base642Byte(privateText);
        byte[] privateTextByte = privateText.toByteArray();
        byte[] publicTextByte = RSAUtil.privateDecrypt(privateTextByte, privateKey);
        BigInteger message = new BigInteger(publicTextByte);

        return message;
    }
}
