package com.sjinc.cvemonitor.dto.osv;

import java.util.List;

public class OsvBatchRequest {
    private List<OsvQuery> queries;

    public OsvBatchRequest(List<OsvQuery> queries) { this.queries = queries; }
    public List<OsvQuery> getQueries() { return queries; }
}