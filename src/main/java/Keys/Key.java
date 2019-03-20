package Keys;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * 存储rsa，pailler的密钥参数
 */
public class Key implements Serializable {
	private BigInteger p;
	private BigInteger q;
	private BigInteger fi;
	private BigInteger tmp;
	public BigInteger n;// paillier、rsa公钥
	public BigInteger d;// rsa算法私钥
	public BigInteger e = new BigInteger("65537");
	public BigInteger g = new BigInteger("2");
	public BigInteger lambda;// paillier算法私钥

	public Key(int num) {
		p = Util.PrimeGenerate(num);
		q = Util.PrimeGenerate(num);
		n = p.multiply(q);
		fi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		exgcd(e, fi);
		lambda = Util.LCM(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));
	}

	private BigInteger exgcd(BigInteger a, BigInteger b) {
		if (b.equals(BigInteger.ZERO)) {
			d = BigInteger.ONE;
			tmp = BigInteger.ZERO;
			return a;
		}
		BigInteger rec = exgcd(b, a.mod(b));
		BigInteger t = new BigInteger(tmp.toString());
		tmp = d.subtract((a.divide(b)).multiply(tmp));
		d = new BigInteger(t.toString());
		return rec;
	}
}
