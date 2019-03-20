import Algorithm.RSAUtil;
import Utils.Decryption;
import Utils.Encryption;
import Utils.Keys;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;

public class test {
    public static void main(String[] args) throws Exception {
//        Keys.storeAESKey();
        rsaTest();
    }

    public static void aesTest() throws Exception{
        SecretKey key = Keys.getAESKey();
        String message = "陈濛真帅啊！";
        String encodedText = Encryption.aes_encryption(message, key);
        String decodedText = Decryption.aes_decryption(encodedText, key);

        System.out.println("ASE CBC 加密密文：" + encodedText);
        System.out.println("ASE CBC 解密明文：" + decodedText);
    }

    public static void rsaTest() throws Exception{
        PrivateKey privateKey = Keys.getRSAPrivateKey();
        PublicKey publicKey = Keys.getRSAPublicKey();
        BigInteger message1 = new BigInteger("5");
        BigInteger message2 = new BigInteger("6");
        BigInteger message3 = new BigInteger("30");

        BigInteger encodedText1 = Encryption.rsa_encryption(message1, publicKey);
        BigInteger encodedText2 = Encryption.rsa_encryption(message2, publicKey);
        BigInteger encodedText3 = Encryption.rsa_encryption(message3, publicKey);
        BigInteger pk = new BigInteger(privateKey.getEncoded());
        BigInteger encodedText4 = encodedText1.multiply(encodedText2).mod(pk);
//        System.out.println(RSAUtil.byte2Base64(encodedText1.toByteArray()).length());

        System.out.println("RSA 加密密文1：" + encodedText1.toString());
        System.out.println("RSA 加密密文2：" + encodedText2.toString());
        System.out.println("RSA 加密密文3：" + encodedText3.toString());
        System.out.println("RSA 密文乘积：" + encodedText4.toString());

        BigInteger decodedText = Decryption.rsa_decryption(encodedText4, privateKey);

        System.out.println("RSA 密文相乘后解密明文：" + decodedText.toString());
    }
}
