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

    void good(Connection conn, EntityManager em, JdbcTemplate jdbc, String id) throws Exception {
        // ok: kisa-sql-injection-java-concat
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        // ok: kisa-sql-injection-java-concat
        em.createQuery("FROM User WHERE name = :name").setParameter("name", id);
        // ok: kisa-sql-injection-java-concat
        jdbc.queryForList("SELECT * FROM t WHERE c = ?", id);
    }
}
