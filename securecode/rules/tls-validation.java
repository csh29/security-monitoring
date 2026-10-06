import java.security.cert.X509Certificate;
import javax.net.ssl.*;
import org.apache.http.conn.ssl.*;

class TlsValidationTest {

    static class TrustAll implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        // ruleid: kisa-tls-trust-all
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    static class Strict implements X509TrustManager {
        private final X509TrustManager delegate = null;
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        // ok: kisa-tls-trust-all
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
            delegate.checkServerTrusted(chain, authType);
        }
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    void hostnames() throws Exception {
        // ruleid: kisa-tls-trust-all
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        // ruleid: kisa-tls-trust-all
        HostnameVerifier noop = NoopHostnameVerifier.INSTANCE;
        // ruleid: kisa-tls-trust-all
        new org.apache.http.ssl.SSLContextBuilder().loadTrustMaterial(null, new TrustAllStrategy());
        // ok: kisa-tls-trust-all
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> hostname.endsWith(".sjinc.co.kr"));
        // ok: kisa-tls-trust-all
        java.util.function.BiPredicate<String, String> any = (a, b) -> true;
    }
}
