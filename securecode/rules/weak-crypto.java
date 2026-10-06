import javax.crypto.Cipher;
import java.security.MessageDigest;
import org.apache.commons.codec.digest.DigestUtils;

class WeakCryptoTest {
    void run(String s) throws Exception {
        // ruleid: kisa-weak-crypto-cipher
        Cipher c1 = Cipher.getInstance("DES/CBC/PKCS5Padding");
        // ruleid: kisa-weak-crypto-cipher
        Cipher c2 = Cipher.getInstance("AES");
        // ruleid: kisa-weak-crypto-cipher
        Cipher c3 = Cipher.getInstance("AES/ECB/PKCS5Padding");
        // ok: kisa-weak-crypto-cipher
        Cipher c4 = Cipher.getInstance("AES/GCM/NoPadding");
        // ruleid: kisa-weak-crypto-hash
        MessageDigest m1 = MessageDigest.getInstance("MD5");
        // ruleid: kisa-weak-crypto-hash
        MessageDigest m2 = MessageDigest.getInstance("SHA-1");
        // ok: kisa-weak-crypto-hash
        MessageDigest m3 = MessageDigest.getInstance("SHA-256");
        // ruleid: kisa-weak-crypto-hash
        String h1 = DigestUtils.md5Hex(s);
        // ok: kisa-weak-crypto-hash
        String h2 = DigestUtils.sha256Hex(s);
    }
}
