package com.sjinc.cvemonitor.dto.osv;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.sjinc.cvemonitor.dto.cve.OsvBatchResultItem;

import java.util.List;

/** OSV /v1/querybatch 응답. results는 요청 queries와 같은 순서로 매칭된다. */
@JsonIgnoreProperties(ignoreUnknown = true)
public class OsvBatchResponse {
    private List<OsvBatchResultItem> results;

    public List<OsvBatchResultItem> getResults() { return results; }
    public void setResults(List<OsvBatchResultItem> results) { this.results = results; }
}
