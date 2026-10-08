package com.sjinc.securitymonitor.config;

import jakarta.servlet.MultipartConfigElement;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.MultipartConfigFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.unit.DataSize;

@Configuration
public class SecureCodeUploadConfig {

    /**
     * 업로드 크기 상한. 이 시스템에서 파일을 받는 곳은 코드 점검 소스 zip 하나다(SecureCodeController.scanUpload).
     * Spring 기본값(파일 1MB)으로는 프로젝트 소스 zip이 전부 거부돼서 securecode.upload.max-bytes(기본 500MB)로 올린다.
     * 받은 파일은 메모리가 아니라 임시 파일로 받는다(fileSizeThreshold 0). 압축을 푼 크기·파일 수 상한은 따로 있다(SourceArchiveExtractor).
     */
    @Bean
    public MultipartConfigElement multipartConfigElement(
            @Value("${securecode.upload.max-bytes:524288000}") long maxBytes) {
        MultipartConfigFactory factory = new MultipartConfigFactory();
        factory.setMaxFileSize(DataSize.ofBytes(maxBytes));
        factory.setMaxRequestSize(DataSize.ofBytes(maxBytes + 1024 * 1024));
        factory.setFileSizeThreshold(DataSize.ofBytes(0));
        return factory.createMultipartConfig();
    }
}
