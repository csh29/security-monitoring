package com.sjinc.cvemonitor.domain;

/** 버전 변경(from → to)의 폭. VersionJumpClassifier가 계산한다. */
public enum VersionJump {
    PATCH, MINOR, MAJOR,
    /** 버전을 해석할 수 없거나, 올리는 게 아니라 낮추거나 그대로 둔 경우 — 사람이 봐야 한다. */
    UNKNOWN
}
