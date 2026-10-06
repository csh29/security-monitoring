import javax.annotation.PostConstruct;

@Service
class OrderService {
    private String currentUserId;
    private final OrderRepository repository;
    private static int counter;
    private String cache;

    OrderService(OrderRepository repository) {
        this.repository = repository;
        // ok: kisa-singleton-field-write
        this.cache = "init";
    }

    @PostConstruct
    void init() {
        // ok: kisa-singleton-field-write
        cache = "ready";
    }

    public void order(String userId) {
        // ruleid: kisa-singleton-field-write
        this.currentUserId = userId;
        // ruleid: kisa-singleton-field-write
        cache = userId;
        String local;
        // ok: kisa-singleton-field-write
        local = userId;
    }
}

class PlainObject {
    private String value;

    public void set(String v) {
        // ok: kisa-singleton-field-write
        this.value = v;
    }
}

@SpringBootApplication
class CrmApplication {
    // ok: kisa-debug-main-method
    public static void main(String[] args) {
    }
}

class DebugTool {
    // ruleid: kisa-debug-main-method
    public static void main(String[] args) {
        System.out.println("test");
    }
}

class Holder {
    private String[] roles;
    private int[] codes = {1, 2};

    public String[] getRoles() {
        // ruleid: kisa-private-array-returned
        return roles;
    }

    public int[] getCodes() {
        // ok: kisa-private-array-returned
        return codes.clone();
    }

    public void setRoles(String[] newRoles) {
        // ruleid: kisa-private-array-assigned
        this.roles = newRoles;
    }

    public void setRolesSafe(String[] newRoles) {
        // ok: kisa-private-array-assigned
        this.roles = newRoles.clone();
    }
}

interface OrderRepository {
}
