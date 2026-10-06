package com.sjinc.securitymonitor.controller;

import com.sjinc.securitymonitor.domain.ComCd;
import com.sjinc.securitymonitor.dto.comcd.ComCdRequest;
import com.sjinc.securitymonitor.security.RequiresProgram;
import com.sjinc.securitymonitor.service.comcd.ComCdService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 공통코드 관리 화면 우측(디테일 코드 그리드)과, 다른 화면들이 select를 채울 때 호출하는 API.
 * group은 항상 필수 — 어떤 그룹의 코드인지 없이는 의미가 없다. select용 호출(사용중인 코드만)은
 * 로그인한 누구나 쓸 수 있어야 화면들의 select가 채워지므로 열어두지만, 비활성 코드까지 보는
 * includeInactive=true(관리 화면 전용)와 저장/삭제는 "com-cd-mng" 권한이 필요하다.
 *
 * <p>저장/삭제는 {@code @RequiresProgram}으로 다른 컨트롤러와 똑같이 선언한다. getCodes만
 * {@code @PreAuthorize}를 쓰는 이유는 includeInactive가 URL 경로가 아니라 쿼리 파라미터 값이라
 * {@code @RequiresProgram}(요청 내용과 무관하게 메서드 전체에 적용) 하나로는 "이 파라미터일
 * 때만 권한을 요구"를 표현할 수 없기 때문이다 — 이런 요청 내용 의존적 예외만 여기 남겨뒀다.
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/com-cds")
public class ComCdController {

    private final ComCdService comCdService;

    @GetMapping
    @PreAuthorize("!#includeInactive or @programAccess.check(authentication.name, 'com-cd-mng')")
    public List<ComCd> getCodes(@RequestParam String group,
                                      @RequestParam(required = false, defaultValue = "false") boolean includeInactive) {
        return includeInactive
                ? comCdService.getAllCodesByGroup(group)
                : comCdService.getCodesByGroup(group);
    }

    @PostMapping
    @RequiresProgram("com-cd-mng")
    public ComCd saveCode(@RequestBody ComCdRequest request) {
        return comCdService.saveCode(request);
    }

    @DeleteMapping("/{id}")
    @RequiresProgram("com-cd-mng")
    public void deleteCode(@PathVariable Long id) {
        comCdService.deleteCode(id);
    }
}
