package com.sai.cvemonitor.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record NvdResponse(
        int resultsPerPage,
        int startIndex,
        int totalResults,
        List<Vulnerability> vulnerabilities
) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Vulnerability(CveItem cve) {}
}
