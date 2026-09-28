package com.sjinc.cvemonitor.domain;

/** mvn dependency:list로 해석된 의존성 하나 (버전까지 확정된 상태). */
public record MavenDependency(String groupId, String artifactId, String version) {

    /** OSV package.name 형식: "groupId:artifactId" */
    public String toOsvPackageName() {
        return groupId + ":" + artifactId;
    }
}