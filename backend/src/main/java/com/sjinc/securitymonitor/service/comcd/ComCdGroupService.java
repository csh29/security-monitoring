package com.sjinc.securitymonitor.service.comcd;

import com.sjinc.securitymonitor.domain.ComCdGroup;
import com.sjinc.securitymonitor.dto.comcd.ComCdGroupRequest;
import com.sjinc.securitymonitor.repository.ComCdGroupRepository;
import com.sjinc.securitymonitor.repository.ComCdRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/** 공통코드 마스터(그룹)의 조회/저장/삭제. 저장/삭제는 공통코드마스터 관리 화면, 조회는 두 공통코드 화면이 쓴다. */
@Service
@RequiredArgsConstructor
public class ComCdGroupService {

    private final ComCdGroupRepository comCdGroupRepository;
    private final ComCdRepository comCdRepository;

    @Transactional(readOnly = true)
    public List<ComCdGroup> getAllGroups() {
        return comCdGroupRepository.findAllByOrderBySortOrderAsc();
    }

    /** request.codeGroup()이 이미 존재하면 수정, 아니면 신규 등록. */
    @Transactional
    public ComCdGroup saveGroup(ComCdGroupRequest request) {
        ComCdGroup group = ComCdGroup.builder()
                .codeGroup(request.codeGroup())
                .groupName(request.groupName())
                .sortOrder(request.sortOrder())
                .useYn(request.useYn())
                .remark(request.remark())
                .build();
        return comCdGroupRepository.save(group);
    }

    /** 그룹을 지우면 그 그룹에 딸린 디테일 코드도 고아로 남기지 않고 함께 지운다. */
    @Transactional
    public void deleteGroup(String codeGroup) {
        comCdRepository.deleteAllByCodeGroup(codeGroup);
        comCdGroupRepository.deleteById(codeGroup);
    }
}
