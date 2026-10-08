import java.sql.*;
import javax.persistence.EntityManager;
import org.springframework.jdbc.core.JdbcTemplate;

class SqlInjectionTest {
    void bad(Connection conn, Statement stmt, EntityManager em, JdbcTemplate jdbc, String id) throws Exception {
        // ruleid: kisa-sql-injection-java-concat
        stmt.executeQuery("SELECT * FROM users WHERE id = '" + id + "'");
        String sql = "DELETE FROM users WHERE id = " + id;
        // ruleid: kisa-sql-injection-java-concat
        stmt.executeUpdate(sql);
        // ruleid: kisa-sql-injection-java-concat
        em.createQuery(String.format("FROM User WHERE name = '%s'", id));
        // ruleid: kisa-sql-injection-java-concat
        jdbc.queryForList("SELECT * FROM t WHERE c = " + id);
    }

    // 변수에 먼저 만든 "문자열 + 값 + 문자열" — 가장 흔한 모양인데 예전 규칙은 바깥 모양만 봐서 놓쳤다(OWASP Benchmark 0건).
    void badWrapped(Connection conn, Statement stmt, JdbcTemplate jdbc, String bar) throws Exception {
        String sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD='" + bar + "'";
        // ruleid: kisa-sql-injection-java-concat
        stmt.execute(sql);
        String call = "{call " + bar + "}";
        // ruleid: kisa-sql-injection-java-concat
        CallableStatement cs = conn.prepareCall(call);
        // ruleid: kisa-sql-injection-java-concat
        jdbc.queryForLong("SELECT count(*) FROM t WHERE c = '" + bar + "'");
        String q;
        q = "UPDATE t SET a = '" + bar + "' WHERE id = 1";
        // ruleid: kisa-sql-injection-java-concat
        stmt.executeUpdate(q);
    }

    void good(Connection conn, EntityManager em, JdbcTemplate jdbc, String id) throws Exception {
        // ok: kisa-sql-injection-java-concat
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        // ok: kisa-sql-injection-java-concat
        em.createQuery("FROM User WHERE name = :name").setParameter("name", id);
        // ok: kisa-sql-injection-java-concat
        jdbc.queryForList("SELECT * FROM t WHERE c = ?", id);
    }
}
