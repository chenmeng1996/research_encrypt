package Utils;

import Algorithm.AESUtil;
import Algorithm.RSAUtil;

import javax.crypto.SecretKey;
import java.io.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Keys {
    //产生AES密钥，并将密钥存储在本地
    public static void storeAESKey() throws IOException {
        //产生AES字节密钥
        byte[] secretBytes = AESUtil.generateAESSecretKey();
        //字节密钥转换成base64字符串，以便存储
        String secretString = AESUtil.byte2Base64(secretBytes);
        //存储字符串到txt文本
        String path = "/Users/chenmeng/AES_key.txt";
        writeTxt(secretString, path);
    }

    //读取AES密钥
    public static SecretKey getAESKey() throws IOException {
        //从txt读取AES密钥字符串
        String path = "/Users/chenmeng/AES_key.txt";
        String result = readTxt(path);
        //字符串 转 byte[]
        byte[] secretBytes = AESUtil.base642Byte(result);
        //byte密钥 转 key对象
        SecretKey key = AESUtil.restoreSecretKey(secretBytes);
        return key;
    }

    //产生RSA公钥和私钥，并将密钥存储在本地
    public static void storeRSAKey() throws Exception {
        //产生RSA的公钥和私钥
        KeyPair keyPair = RSAUtil.getKeyPair();
        //获得私钥字符串
        String privateKeyString = RSAUtil.getPrivateKey(keyPair);
        //获得公钥字符串
        String publicKeyString = RSAUtil.getPublicKey(keyPair);

        //存储私钥和公钥字符串到txt文本
        String path = "/Users/chenmeng/RSA_private_key.txt";
        writeTxt(privateKeyString, path);
        path = "/Users/chenmeng/RSA_public_key.txt";
        writeTxt(publicKeyString, path);
    }

    //读取RSA私钥
    public static PrivateKey getRSAPrivateKey() throws Exception {
        //从txt读取RSA私钥字符串
        String path = "/Users/chenmeng/RSA_private_key.txt";
        String privateKeyString = readTxt(path);

        PrivateKey privateKey = RSAUtil.string2PrivateKey(privateKeyString);
        return privateKey;
    }
    //读取RSA公钥
    public static PublicKey getRSAPublicKey() throws Exception {
        //从txt读取RSA私钥字符串
        String path = "/Users/chenmeng/RSA_public_key.txt";
        String publicKeyString = readTxt(path);

        PublicKey publicKey = RSAUtil.string2PublicKey(publicKeyString);
        return publicKey;
    }

    //从txt中读取字符串
    public static String readTxt(String path){
        StringBuilder result = new StringBuilder();
        try{
            BufferedReader br = new BufferedReader(new FileReader(path));//构造一个BufferedReader类来读取文件
            String s = null;
            while((s = br.readLine())!=null){//使用readLine方法，一次读一行
                result.append(System.lineSeparator()+s);
            }
            br.close();
        }catch(Exception e){
            e.printStackTrace();
        }
        return result.toString();
    }

    //写入txt
    public static void writeTxt(String content, String path) throws IOException{
        FileWriter fos = new FileWriter(path);
        fos.write(content);
        fos.close();
    }
}
