import java.nio.charset.StandardCharsets;
import java.security.*;
import org.apache.commons.codec.digest.DigestUtils;

class WeakKeySaltTest {
    void keys() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        // ruleid: kisa-weak-key-length
        rsa.initialize(1024);

        KeyPairGenerator strong = KeyPairGenerator.getInstance("RSA");
        // ok: kisa-weak-key-length
        strong.initialize(2048);

        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        // ok: kisa-weak-key-length
        ec.initialize(256);
    }

    String hash(String password, String fileContent) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        // ruleid: kisa-hash-without-salt
        byte[] h = md.digest(password.getBytes(StandardCharsets.UTF_8));
        // ruleid: kisa-hash-without-salt
        String hex = DigestUtils.sha256Hex(password);
        // ok: kisa-hash-without-salt
        byte[] checksum = md.digest(fileContent.getBytes(StandardCharsets.UTF_8));
        return hex;
    }
}
