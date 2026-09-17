package com.sjinc.cvemonitor.service.commoncode;

import com.sjinc.cvemonitor.domain.CommonCodeGroup;
import com.sjinc.cvemonitor.dto.commoncode.CommonCodeGroupRequest;
import com.sjinc.cvemonitor.repository.CommonCodeGroupRepository;
import com.sjinc.cvemonitor.repository.CommonCodeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/** 공통코드관리 화면 좌측(마스터) 그룹 목록의 조회/저장/삭제를 담당한다. */
@Service
@RequiredArgsConstructor
public class CommonCodeGroupService {

    private final CommonCodeGroupRepository commonCodeGroupRepository;
    private final CommonCodeRepository commonCodeRepository;

    @Transactional(readOnly = true)
    public List<CommonCodeGroup> getAllGroups() {
        return commonCodeGroupRepository.findAllByOrderBySortOrderAsc();
    }

    /** request.codeGroup()이 이미 존재하면 수정, 아니면 신규 등록. */
    @Transactional
    public CommonCodeGroup saveGroup(CommonCodeGroupRequest request) {
        CommonCodeGroup group = CommonCodeGroup.builder()
                .codeGroup(request.codeGroup())
                .groupName(request.groupName())
                .sortOrder(request.sortOrder())
                .useYn(request.useYn())
                .build();
        return commonCodeGroupRepository.save(group);
    }

    /** 그룹을 지우면 그 그룹에 딸린 디테일 코드도 고아로 남기지 않고 함께 지운다. */
    @Transactional
    public void deleteGroup(String codeGroup) {
        commonCodeRepository.deleteAllByCodeGroup(codeGroup);
        commonCodeGroupRepository.deleteById(codeGroup);
    }
}
