package test;

import Algorithm.AESUtil;
import Keys.*;
//import org.apache.commons.codec.binary.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;

public class Test {
    private static AESUtil aes = new AESUtil();
    private static final String plain_string = "明天会更好";
    private static final Integer plain_int_1 = 7;
    private static final Integer plain_int_2 = 3;

    public static void main(String[] arg) {

        try {
            Init_Keys init_keys = new Init_Keys(2018);

            SecretKeySpec aesKey = init_keys.getKeyAes();
            Key homomorphicKey= init_keys.getKey();

            String secret_int_1 = EncryptData.encryptPlus(homomorphicKey, plain_int_1.toString());
            String secret_int_2 = EncryptData.encryptPlus(homomorphicKey, plain_int_2.toString());
            String secret_sum = Encrypt.add(new BigInteger(secret_int_1), new BigInteger(secret_int_2)).toString();
            String plain_sum = DecryptData.DecryptPlus(homomorphicKey, secret_sum);
            System.out.println(plain_int_1 + " Paillier加密：" + secret_int_1);
            System.out.println(plain_int_2 + " Paillier加密：" + secret_int_2);
            System.out.println("两个密文之和：" + secret_sum);
            System.out.println("密文之和解密：" + plain_sum);

            System.out.println();

            secret_int_1 = EncryptData.encryptMulti(homomorphicKey, plain_int_1.toString());
            secret_int_2 = EncryptData.encryptMulti(homomorphicKey, plain_int_2.toString());
            secret_sum = Encrypt.multi(new BigInteger(secret_int_1), new BigInteger(secret_int_2)).toString();
            plain_sum = DecryptData.DecryptMulti(homomorphicKey, secret_sum);
            System.out.println(plain_int_1 + " RSA加密：" + secret_int_1);
            System.out.println(plain_int_2 + " RSA加密：" + secret_int_2);
            System.out.println("两个密文之积：" + secret_sum);
            System.out.println("密文之积解密：" + plain_sum);

            System.out.println();

            String secret_string = EncryptData.encryptAes(aesKey, plain_string);
            String plain = DecryptData.DecryptAes(aesKey, secret_string);
            System.out.println(plain_string + " AES加密：" + secret_string);
            System.out.println("AES解密：" + plain);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
