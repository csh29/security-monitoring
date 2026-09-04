package com.sjinc.cvemonitor.dto.scan;

/** 화면에서 "검증" 버튼 클릭 시 전송하는 요청. */
public record ScanRequest(String repoUrl, String branch) {

}