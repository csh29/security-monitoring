package com.sjinc.cvemonitor.mvc;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * REST API 전반의 "요청이 잘못됨"을 400으로 내려준다.
 *
 * <p>서비스 계층이 입력 검증에 쓰는 {@link IllegalArgumentException}을 그냥 두면 500이 나가는데,
 * 그러면 호출한 화면이 "내가 잘못 보낸 것"과 "서버가 터진 것"을 구분할 수 없다. 같은 처리를
 * 두 번째로 쓰게 되는 시점(앱 등록 URL 검증)이라 컨트롤러마다 복사하는 대신 위로 올렸다.
 *
 * <p>ScanController에는 같은 핸들러가 그대로 남아 있는데, 중복이 아니라 필요해서다 — 그 컨트롤러는
 * {@code @ExceptionHandler(Exception.class)}를 따로 갖고 있고, 컨트롤러 안의 핸들러가 이 advice보다
 * 먼저 매칭되기 때문에 지우면 IllegalArgumentException이 그 catch-all로 흘러 500이 된다.
 *
 * <p>{@code annotations = RestController.class}로 범위를 REST 컨트롤러로 한정한다 — 화면을
 * 반환하는 {@link ViewController}까지 걸리면 오류가 HTML 대신 문자열 본문으로 나가버린다.
 */
@RestControllerAdvice(annotations = RestController.class)
@Slf4j
public class ApiExceptionAdvice {

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public String handleInvalidRequest(IllegalArgumentException e) {
        log.debug("잘못된 요청: {}", e.getMessage());
        return e.getMessage();
    }
}
