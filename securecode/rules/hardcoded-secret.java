class HardcodedSecretTest {
    // ruleid: kisa-hardcoded-secret-java
    private static final String DB_PASSWORD = "P@ssw0rd123";
    // ruleid: kisa-hardcoded-secret-java
    String apiToken = "ghp_abcdef1234567890";
    // ok: kisa-hardcoded-secret-java
    private static final String PASSWORD_PARAM = "password";
    // ok: kisa-hardcoded-secret-java
    String passwordMessage = "비밀번호가 올바르지 않습니다";
    // ok: kisa-hardcoded-secret-java
    String password = "";
    // ok: kisa-hardcoded-secret-java
    private static final String INITIAL_PASSWORD_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    // ok: kisa-hardcoded-secret-java
    @Value("${db.password}") String dbPassword;

    void connect(DataSourceConfig ds) {
        // ruleid: kisa-hardcoded-secret-java
        ds.setPassword("admin1234");
        // ok: kisa-hardcoded-secret-java
        ds.setPassword(System.getenv("DB_PASSWORD"));
    }
}
