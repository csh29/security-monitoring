package com.sjinc.securitymonitor.dto.nvd;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/** NVD CVE의 {@code configurations} 배열 원소 하나. 실제 영향 버전 범위(cpeMatch)를 담는 최상위 구조. */
@JsonIgnoreProperties(ignoreUnknown = true)
public class NvdConfiguration {

    private List<NvdNode> nodes;

    public List<NvdNode> getNodes() { return nodes; }
    public void setNodes(List<NvdNode> nodes) { this.nodes = nodes; }
}
