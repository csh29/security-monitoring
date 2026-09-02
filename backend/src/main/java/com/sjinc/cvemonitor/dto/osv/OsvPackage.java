package com.sjinc.cvemonitor.dto.osv;

public class OsvPackage {
    private String name;      // "groupId:artifactId"
    private String ecosystem; // "Maven"

    public OsvPackage() {}
    public OsvPackage(String name, String ecosystem) {
        this.name = name;
        this.ecosystem = ecosystem;
    }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getEcosystem() { return ecosystem; }
    public void setEcosystem(String ecosystem) { this.ecosystem = ecosystem; }
}