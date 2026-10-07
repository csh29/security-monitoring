package com.sjinc.securitymonitor.dto.securecode;

import com.sjinc.securitymonitor.service.securecode.DollarTraceMerger;
import com.sjinc.securitymonitor.service.securecode.UserScopeFindings;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecureCodeFindingViewTest {

    @Test
    void 매퍼_판정은_근거_마지막_줄에서_대상_식을_꺼낸다() {
        // 한 줄에 ${}가 둘이면(ums_log_${loginBrndzCd}_${ym}) 행마다 자기 식이 보여야 구분된다.
        assertThat(SecureCodeFindingView.traceTarget(DollarTraceMerger.RULE_ID, List.of(
                "Crd020Controller.java:36 paramData.put(\"loginBrndzCd\", ...)",
                "crd020.xml:35 ${loginBrndzCd} (crd020.selectSms)"))).isEqualTo("${loginBrndzCd}");
        assertThat(SecureCodeFindingView.traceTarget(DollarTraceMerger.RULE_ID, List.of(
                "crd020.xml:55 ${ym.substring(2)} (crd020.selectSms)"))).isEqualTo("${ym.substring(2)}");
        assertThat(SecureCodeFindingView.traceTarget(UserScopeFindings.RULE_ID, List.of(
                "order.xml:6 #{userId} (order.list)"))).isEqualTo("#{userId}");
    }

    @Test
    void 매퍼_판정이_아니거나_근거가_없으면_대상_식이_없다() {
        assertThat(SecureCodeFindingView.traceTarget("kisa-ssrf-dynamic-url", List.of("S.java:3 new URL(\"${x}\")"))).isNull();
        assertThat(SecureCodeFindingView.traceTarget(DollarTraceMerger.RULE_ID, List.of())).isNull();
    }
}
