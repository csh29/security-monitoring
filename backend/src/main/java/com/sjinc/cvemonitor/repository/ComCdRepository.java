package com.sjinc.cvemonitor.repository;

import com.sjinc.cvemonitor.domain.ComCd;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ComCdRepository extends JpaRepository<ComCd, Long> {

    /** 화면의 select 하나를 채울 때 쓰는 조회 — 지정한 그룹의 사용중인 코드만 정렬순서대로. */
    List<ComCd> findByCodeGroupAndUseYnOrderBySortOrderAsc(String codeGroup, String useYn);

    /** 공통코드 관리 화면에서 그룹 하나를 선택했을 때의 디테일 그리드 — 사용여부와 상관없이 전부 보여준다. */
    List<ComCd> findByCodeGroupOrderBySortOrderAsc(String codeGroup);

    /** 마스터(그룹) 삭제 시 딸린 디테일 코드도 함께 지운다. */
    void deleteAllByCodeGroup(String codeGroup);

    /** 설정용 공통코드 하나(ComCdService.isEnabled). (그룹, 코드값)에 유일 제약이 없어 중복이 있어도 터지지 않게 첫 번째만 본다. */
    Optional<ComCd> findFirstByCodeGroupAndCodeValueOrderByIdAsc(String codeGroup, String codeValue);
}
