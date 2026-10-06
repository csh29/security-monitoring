package com.sjinc.securitymonitor.dto.osv;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** ranges[].events[] 항목 하나. 실제로는 이 넷 중 하나의 필드만 채워져서 내려온다. */
@JsonIgnoreProperties(ignoreUnknown = true)
public class OsvEvent {
    private String introduced;
    private String fixed;
    @JsonProperty("last_affected")
    private String lastAffected;
    private String limit;

    public String getIntroduced() { return introduced; }
    public void setIntroduced(String introduced) { this.introduced = introduced; }
    public String getFixed() { return fixed; }
    public void setFixed(String fixed) { this.fixed = fixed; }
    public String getLastAffected() { return lastAffected; }
    public void setLastAffected(String lastAffected) { this.lastAffected = lastAffected; }
    public String getLimit() { return limit; }
    public void setLimit(String limit) { this.limit = limit; }
}
