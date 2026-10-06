import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import org.apache.commons.io.FilenameUtils;
import org.springframework.web.multipart.MultipartFile;

class FileUploadTest {
    void bad(MultipartFile file, String uploadDir) throws Exception {
        String name = file.getOriginalFilename();
        // ruleid: kisa-file-upload-original-filename-path
        File dest = new File(uploadDir, name);
        // ruleid: kisa-file-upload-save
        file.transferTo(dest);
    }

    void badPath(MultipartFile file, Path dir) throws Exception {
        // ruleid: kisa-file-upload-original-filename-path
        Path target = dir.resolve(file.getOriginalFilename());
        // ruleid: kisa-file-upload-save
        Files.copy(file.getInputStream(), target);
    }

    void good(MultipartFile file, String uploadDir) throws Exception {
        String ext = FilenameUtils.getExtension(file.getOriginalFilename());
        // ok: kisa-file-upload-original-filename-path
        File dest = new File(uploadDir, UUID.randomUUID() + "." + ext);
        // ruleid: kisa-file-upload-save
        file.transferTo(dest);
    }
}
