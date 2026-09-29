package com.sjinc.cvemonitor.service.comcd;

import com.sjinc.cvemonitor.domain.ComCd;
import com.sjinc.cvemonitor.dto.comcd.ComCdRequest;
import com.sjinc.cvemonitor.repository.ComCdRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/** 공통코드 관리 화면(우측 디테일 조회/저장/삭제)과, 화면들이 select를 채울 때 호출하는 공통코드 조회를 담당한다. */
@Service
@RequiredArgsConstructor
public class ComCdService {

    private final ComCdRepository comCdRepository;

    /** 다른 화면의 select 하나를 채울 때 호출 — 지정한 그룹의 사용중인 코드만 정렬순서대로. */
    @Transactional(readOnly = true)
    public List<ComCd> getCodesByGroup(String codeGroup) {
        return comCdRepository.findByCodeGroupAndUseYnOrderBySortOrderAsc(codeGroup, "Y");
    }

    /** 공통코드 관리 화면에서 그룹을 선택했을 때의 디테일 그리드 — 비활성 코드도 관리해야 하므로 사용여부와 무관하게 전부. */
    @Transactional(readOnly = true)
    public List<ComCd> getAllCodesByGroup(String codeGroup) {
        return comCdRepository.findByCodeGroupOrderBySortOrderAsc(codeGroup);
    }

    /** request.id()가 있으면 수정, 없으면 신규 등록. */
    @Transactional
    public ComCd saveCode(ComCdRequest request) {
        ComCd code = ComCd.builder()
                .id(request.id())
                .codeGroup(request.codeGroup())
                .codeValue(request.codeValue())
                .codeName(request.codeName())
                .sortOrder(request.sortOrder())
                .useYn(request.useYn())
                .remark(request.remark())
                .build();
        return comCdRepository.save(code);
    }

    @Transactional
    public void deleteCode(Long id) {
        comCdRepository.deleteById(id);
    }
}
