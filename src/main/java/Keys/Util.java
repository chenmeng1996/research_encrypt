package Keys;

import java.math.BigInteger;
import java.util.Random;

/**
 * 工具类
 */
public class Util {
    private static final int ERR_VAL = 10;

    //字节数组 转 字符串
    public static String BytesToString(byte[] bytes) {

        String result = "";
        for (int i = 0; i < bytes.length; i++) {
            int temp = bytes[i] & 0xff;
            String tempHex = Integer.toHexString(temp);

            if (tempHex.length() < 2)
                result += "0" + tempHex;

            else result += tempHex;
        }


        return result;


    }
    //字符串 转 字节数组
    public static byte[] StringToBytes(String hexString) {
        if (hexString == null || hexString.equals("")) {
            return null;
        }
        hexString = hexString.toUpperCase();
        int length = hexString.length() / 2;
        char[] hexChars = hexString.toCharArray();
        byte[] d = new byte[length];
        for (int i = 0; i < length; i++) {
            int pos = i * 2;
            d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
        }
        return d;
    }

    private static byte charToByte(char c) {
        return (byte) "0123456789ABCDEF".indexOf(c);
    }

    //计算两个数的最大公约数
    public static BigInteger GCD(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO))
            return a;
        else
            return GCD(b, a.mod(b));
    }

    //计算两个数的最小公倍数
    public static BigInteger LCM(BigInteger a, BigInteger b) {
        return a.multiply(b).divide(GCD(a, b));
    }

    //产生指定长度的随机素数
    public static BigInteger PrimeGenerate(int num) {
        //得到具有指定长度的可能的素数
        BigInteger start = BigInteger.probablePrime(num, new Random());
        while (!start.isProbablePrime(ERR_VAL)) { // Miller-Rabin Algorithm
            start = BigInteger.probablePrime(num, new Random());

        }
        return start;
    }

}
