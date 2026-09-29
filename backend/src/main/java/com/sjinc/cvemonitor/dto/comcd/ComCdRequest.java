package com.sjinc.cvemonitor.dto.comcd;

/** 공통코드 관리 화면(우측 디테일)의 "저장" 버튼 클릭 시 전송하는 요청. id가 있으면 수정, 없으면 신규 등록. */
public record ComCdRequest(Long id, String codeGroup, String codeValue, String codeName,
                                 Integer sortOrder, String useYn, String remark) {
}
