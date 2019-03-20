package Keys;

import java.math.BigInteger;
import java.util.Random;

/**
 * 对数字进行加密和解密的类
 */
public class Encrypt {
	//加法解密
	public static BigInteger encryptionPlus(Key k, Integer data) {
		BigInteger r = new BigInteger(64, new Random());
		BigInteger m = new BigInteger(data.toString());
		return k.g.modPow(m, k.n.pow(2)).multiply(r.modPow(k.n, k.n.pow(2))).mod(k.n.pow(2));
	}
	//乘法解密
	public static BigInteger encryptionMulti(Key k, Integer data) {
		BigInteger m = new BigInteger(data.toString());
		return m.modPow(k.e, k.n);
	}
	//加法解密
	public static BigInteger decryptionPlus(Key k, BigInteger code) {
		BigInteger nsquare = k.n.pow(2);
		BigInteger u = k.g.modPow(k.lambda, nsquare).subtract(BigInteger.ONE).divide(k.n).modInverse(k.n);
		return code.modPow(k.lambda, nsquare).subtract(BigInteger.ONE).divide(k.n).multiply(u).mod(k.n);
	}
	//乘法解密
	public static BigInteger decryptionMulti(Key k, BigInteger code) {
		return code.modPow(k.d, k.n);
	}
	//两个数字加法
	public static BigInteger add(BigInteger a, BigInteger b) {
		return a.multiply(b);
	}
	//两个数字乘法
	public static BigInteger multi(BigInteger a, BigInteger b) {
		return a.multiply(b);
	}

}
