import java.util.Random;
import java.security.SecureRandom;

class InsecureRandomTest {
    void run() {
        // ruleid: kisa-insecure-random
        Random r = new Random();
        // ruleid: kisa-insecure-random
        double d = Math.random();
        // ok: kisa-insecure-random
        SecureRandom sr = new SecureRandom();
    }
}
