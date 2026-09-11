package com.sjinc.cvemonitor.dto.osv;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/** /v1/vulns/{id} 응답의 affected[] 항목 하나 (패키지 하나 + 그 패키지의 영향 범위). */
@JsonIgnoreProperties(ignoreUnknown = true)
public class OsvAffected {
    @com.fasterxml.jackson.annotation.JsonProperty("package")
    private OsvPackage packageInfo;
    private List<OsvRange> ranges;

    public OsvPackage getPackageInfo() { return packageInfo; }
    public void setPackageInfo(OsvPackage packageInfo) { this.packageInfo = packageInfo; }
    public List<OsvRange> getRanges() { return ranges; }
    public void setRanges(List<OsvRange> ranges) { this.ranges = ranges; }
}
