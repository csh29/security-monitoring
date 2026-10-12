import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

class PermissionTest {

    void file(File f) {
        // ruleid: kisa-insecure-file-permission
        f.setWritable(true, false);
        // ruleid: kisa-insecure-file-permission
        f.setReadable(true, false);
        // ok: kisa-insecure-file-permission
        f.setWritable(true, true);
        // ok: kisa-insecure-file-permission
        f.setReadable(true);
    }

    void posix(Path p) throws Exception {
        // ruleid: kisa-insecure-file-permission
        Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwxrwxrwx"));
        // ruleid: kisa-insecure-file-permission
        Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-rw-rw-"));
        // ok: kisa-insecure-file-permission
        Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-r-----"));
        // ruleid: kisa-insecure-file-permission
        Set<PosixFilePermission> perms = Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OTHERS_WRITE);
    }
}
