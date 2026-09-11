package com.sjinc.cvemonitor.dto.osv;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/** affected[].ranges[] 항목 하나. type(ECOSYSTEM/SEMVER/GIT)은 fixed 버전 추출에는 필요 없어 매핑하지 않는다. */
@JsonIgnoreProperties(ignoreUnknown = true)
public class OsvRange {
    private List<OsvEvent> events;

    public List<OsvEvent> getEvents() { return events; }
    public void setEvents(List<OsvEvent> events) { this.events = events; }
}
