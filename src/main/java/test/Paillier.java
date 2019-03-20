package test;
/**
 * 密钥生成：
 * 1、随机选择两个大质数p和q满足gcd（pq,(p-1)(q-1)）=1。 这个属性是保证两个质数长度相等。
 * 2、计算 n = pq和λ= lcm (p - 1,q-1)。
 * 3、选择随机整数g使得gcd(L(g^lambda % n^2) , n) = 1,满足g属于n^2;
 * 4、公钥为（N，g）
 * 5、私钥为lambda。
 * :加密
 * 选择随机数r满足
 * 计算密文
 * 其中m为加密信息
 *
 * 解密：
 * m = D(c,lambda) = ( L(c^lambda%n^2)/L(g^lambda%n^2) )%n;
 * 其中L(u) = (u-1)/n;
 */

import java.math.*;
import java.util.*;

public class Paillier {

    //p,q是两个随机的质数， lambda = lcm(p-1, q-1);
    private BigInteger p, q, lambda;

    // n = p*q
    public BigInteger n;

    // nsquare就是n的平方
    public BigInteger nsquare;
    /**
     * 随机选取一个整数 g,g属于小于n的平方中的整数集,且 g 满足:g的lambda次方对n的平方求模后减一后再除与n，
     * 最后再将其与n求最大公约数，且最大公约数等于一。
     * a random integer in Z*_{n^2} where gcd (L(g^lambda mod nsquare), n) = 1.
     */
    private BigInteger g;
    //bitLength 模量
    private int bitLength;

    /**
     * Constructs an instance of the Paillier cryptosystem.
     *
     * @param bitLengthVal
     *            number of bits of modulus 模量
     * @param certainty
     *            The probability that the new BigInteger represents a prime
     *            number will exceed (1 - 2^(-certainty)). The execution time of
     *            this constructor is proportional to the value of this
     *            parameter.
     *带参的构造方法
     */
    public Paillier(int bitLengthVal, int certainty) {
        KeyGeneration(bitLengthVal, certainty);
    }

    /**
     * Constructs an instance of the Paillier cryptosystem with 512 bits of
     * modulus and at least 1-2^(-64) certainty of primes generation.
     * 构造方法
     */
    public Paillier() {
        KeyGeneration(512, 64);
    }

    /**
     * 产生公钥【N,g】       私钥lamada
     * @param bitLengthVal
     *            number of bits of modulus.
     * @param certainty
     *            certainty - 调用方允许的不确定性的度量。
     *            新的 BigInteger 表示素数的概率超出 (1 - 1/2certainty)。
     *            此构造方法的执行时间与此参数的值是成比例的。
     */
    public void KeyGeneration(int bitLengthVal, int certainty) {
        bitLength = bitLengthVal;
        //构造两个随机生成的正 大质数，长度可能为bitLength/2，它可能是一个具有指定 bitLength 的素数
        p = new BigInteger(bitLength / 2, certainty, new Random());
        q = new BigInteger(bitLength / 2, certainty, new Random());

        //n = p*q;
        n = p.multiply(q);
        //nsquare = n*n;
        nsquare = n.multiply(n);
        //随机生成一个0~100的整数g
        g = new BigInteger( String.valueOf( (int) (  Math.random()*100 ) ));

        //lamada=lcm(p-1,q-1),即lamada是p-1,q-1的最小公倍数
        //lamada=((p-1)*(q-1)) / gcd(p-1,q-1);
        lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))  //(p-1)*(q-1)
                .divide(p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
        //检验g是否符合公式的要求， gcd (L(g^lambda mod nsquare), n) = 1.
        if (g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).gcd(n).intValue() != 1) {
            System.out.println("g is not good. Choose g again.");
            System.exit(1);
        }
    }

    /**
     * @param m 明文m
     * @param r 随机的一个整数r
     * @return 返回密文
     * 加密
     */
    public BigInteger Encryption(BigInteger m, BigInteger r) {
        //c = (g^m)*(r^n)modnsquare
        return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);
    }

    public BigInteger Encryption(BigInteger m) {
        //构造一个随机生成的 BigInteger，它是在 0 到 (2numBits - 1)（包括）范围内均匀分布的值。
        BigInteger r = new BigInteger(bitLength, new Random());
        return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);

    }

    /**
     * 利用私钥lamada对密文c进行解密返回明文m
     * 公式：m = ( L((c^lambda) mod nsquare) / L((g^lambda) mod nsquare) ) mod n
     */
    public BigInteger Decryption(BigInteger c) {
        BigInteger u1 = c.modPow(lambda, nsquare);
        BigInteger u2 = g.modPow(lambda, nsquare);
        return (u1.subtract(BigInteger.ONE).divide(n)).multiply(u2.subtract(BigInteger.ONE).divide(n).modInverse(n)).mod(n);
    }

    /**
     * 两个密文的和
     * @param em1
     * @param em2
     * @return
     */
    public BigInteger cipher_add(BigInteger em1, BigInteger em2) {
        return em1.add(em2);
    }

    public static void main(String[] str) {
        //实例化一个不用传参的对象，用默认的数据
        Paillier paillier = new Paillier();
        // 实例化两个数据对象m1,m2，进行加密
        BigInteger m1 = new BigInteger("20");
        BigInteger m2 = new BigInteger("60");

        //加密
        BigInteger em1 = paillier.Encryption(m1);
        BigInteger em2 = paillier.Encryption(m2);

        //输出加密后的结果
        System.out.println("m1加密后为: "+em1);
        System.out.println("m2加密后为: "+em2);

        //输出解密后的结果
        System.out.println("m1加密之后进行解密的结果= "+paillier.Decryption(em1).toString());
        System.out.println("m2加密之后进行解密的结果= "+paillier.Decryption(em2).toString());


        // 测试同态性     D(E(m1)*E(m2) mod n^2) = (m1 + m2) mod n

        // m1+m2,求明文数值的和
        BigInteger sum_m1m2 = m1.add(m2).mod(paillier.n);
        System.out.println("明文的和 : " + sum_m1m2.toString());
        // em1+em2，求密文数值的乘
        BigInteger product_em1em2 = em1.multiply(em2).mod(paillier.nsquare);
        System.out.println("密文的和: " + product_em1em2.toString());
        System.out.println("解密后的 和: " + paillier.Decryption(product_em1em2).toString());

        // 测试同态性 ->   D(E(m1)^m2 mod n^2) = (m1*m2) mod n
        // m1*m2,求明文数值的乘
        BigInteger prod_m1m2 = m1.multiply(m2).mod(paillier.n);
        System.out.println("明文的乘积: " + prod_m1m2.toString());
        // em1的m2次方，再mod paillier.nsquare
        BigInteger expo_em1m2 = em1.modPow(m2, paillier.nsquare);
        System.out.println("密文的结果: " + expo_em1m2.toString());
        System.out.println("解密后的结果: " + paillier.Decryption(expo_em1m2).toString());

        System.out.println("--------------------------------");
        Paillier p = new Paillier();
        BigInteger t1 = new BigInteger("21"); System.out.println("t1 = "+t1.toString());
        BigInteger t2 = new BigInteger("50"); System.out.println("t2 = "+t2.toString());
        BigInteger et1 = p.Encryption(t1); System.out.println("t1 Encryption = "+et1.toString());
        BigInteger et2 = p.Encryption(t2); System.out.println("t2 Encryption = "+et2.toString());

        System.out.println("明文和: "+t1.add(t2).toString());
        System.out.println("加密后的和 : "+p.Encryption(t1.add(t2)).toString());
        System.out.println("解密后的和进行解密："+p.Decryption(p.Encryption(t1.add(t2))));
        System.out.println("--------------------------------");
    }
}

