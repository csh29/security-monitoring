package com.sai.cvemonitor.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record CveItem(
        String id,
        String sourceIdentifier,
        String published,
        String lastModified,
        String vulnStatus,
        List<Description> descriptions
) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Description(String lang, String value) {}
}
