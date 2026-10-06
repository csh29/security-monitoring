import javax.servlet.http.*;
import org.springframework.http.ResponseEntity;

@RestController
class ErrorHandlingTest {

    @GetMapping("/a")
    public ResponseEntity<?> a() {
        try {
            return ResponseEntity.ok(load());
        } catch (Exception e) {
            // ruleid: kisa-error-stacktrace
            e.printStackTrace();
            // ruleid: kisa-error-message-response
            return ResponseEntity.status(500).body(e.getMessage());
        }
    }

    @GetMapping("/b")
    public String b() {
        try {
            return load();
        } catch (RuntimeException ex) {
            // ok: kisa-error-message-response
            return "처리 중 오류가 발생했습니다.";
        }
    }

    @ExceptionHandler(Exception.class)
    public String handle(Exception e) {
        // ruleid: kisa-error-message-response
        return "오류: " + e.getMessage();
    }

    void empty() {
        // ruleid: kisa-error-empty-catch
        try {
            load();
        } catch (Exception e) {}

        // ok: kisa-error-empty-catch
        try {
            load();
        } catch (Exception ignored) {}

        // ok: kisa-error-empty-catch
        try {
            load();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String load() {
        return "x";
    }
}

class NotController {
    String message(Exception e) {
        try {
            return "x";
        } catch (Exception ex) {
            // ok: kisa-error-message-response
            return ex.getMessage();
        }
    }
}
