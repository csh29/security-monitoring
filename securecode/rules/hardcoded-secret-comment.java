class CommentSecretTest {
    // ruleid: kisa-hardcoded-secret-comment
    // 운영 DB password: Prod#2024!
    private String url;

    // ruleid: kisa-hardcoded-secret-comment
    /* api_key = sk-test-1234567890 */
    void a() {
    }

    // ok: kisa-hardcoded-secret-comment
    // 비밀번호는 ${DB_PASSWORD} 환경변수에서 읽는다
    private String b;

    // ok: kisa-hardcoded-secret-comment
    private String jdbc = "jdbc:postgresql://db:5432/crm";

    // ok: kisa-hardcoded-secret-comment
    // password 검증 규칙: 8자 이상
    private String c;

    // ok: kisa-hardcoded-secret-comment
    //        secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(raw));
    private String d;

    // ok: kisa-hardcoded-secret-comment
    //   String decryptedPassword = decrypt(encryptedPassword, keyPair);
    private String e;
}
