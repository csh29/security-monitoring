package com.sjinc.cvemonitor.dto.osv;

import com.fasterxml.jackson.annotation.JsonProperty;

public class OsvQuery {

    @JsonProperty("package")
    private OsvPackage pkg;
    private String version;

    public OsvQuery(OsvPackage pkg, String version) {
        this.pkg = pkg;
        this.version = version;
    }

    public OsvPackage getPkg() { return pkg; }
    public String getVersion() { return version; }
}