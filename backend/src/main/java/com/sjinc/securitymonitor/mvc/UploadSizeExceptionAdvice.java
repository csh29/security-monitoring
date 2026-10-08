package com.sjinc.securitymonitor.mvc;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

/**
 * 업로드 크기 상한(securecode.upload.max-bytes, SecureCodeUploadConfig)을 넘은 요청을 413과 안내 문구로 돌려준다.
 *
 * <p>ApiExceptionAdvice와 따로 두는 이유: 이 예외는 Spring이 요청을 처리할 컨트롤러를 고르기 전(멀티파트 해석 단계)에 나서, 컨트롤러 안의
 * 핸들러나 범위를 REST 컨트롤러로 한정한 advice로는 잡히지 않는다. 그래서 범위 없이 이 예외 하나만 맡는다.
 */
@RestControllerAdvice
public class UploadSizeExceptionAdvice {

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    @ResponseStatus(HttpStatus.PAYLOAD_TOO_LARGE)
    public String handleTooLarge(MaxUploadSizeExceededException e) {
        return "업로드 파일이 너무 큽니다. 빌드 결과물(target·build·node_modules 등)을 빼고 소스만 압축하세요.";
    }
}
