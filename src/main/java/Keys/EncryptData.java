package Keys;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * 通用的（包含数字和字符）的加密
 */
public class EncryptData {

	// 乘法加密
	public static String encryptMulti(Key k, String t) {
		Integer data = Integer.valueOf(t);
		return Encrypt.encryptionMulti(k, data).toString();
	}

	// 加法加密
	public static String encryptPlus(Key k, String t) {
		Integer data = Integer.valueOf(t);
		return Encrypt.encryptionPlus(k, data).toString();
	}

	// AES加密
	public static String encryptAes(SecretKeySpec k, String t) throws Exception {
		// 创建密码器
		Cipher cipher = Cipher.getInstance("AES");
		// 初始化为加密模式的密码器
		cipher.init(Cipher.ENCRYPT_MODE, k);
		byte[] result = cipher.doFinal(t.getBytes());
		String string = Util.BytesToString(result);

		return string;
	}

}
