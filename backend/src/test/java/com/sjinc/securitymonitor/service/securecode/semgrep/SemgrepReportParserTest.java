package com.sjinc.securitymonitor.service.securecode.semgrep;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sjinc.securitymonitor.dto.securecode.SemgrepMatch;
import com.sjinc.securitymonitor.dto.securecode.SemgrepReport;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SemgrepReportParserTest {

    private final SemgrepReportParser parser = new SemgrepReportParser(new ObjectMapper());

    // Semgrep 1.178.0이 윈도우에서 실제로 낸 결과 모양(경로 역슬래시, check_id 접두어, lines는 "requires login").
    private static final String JSON = """
            {
              "version": "1.178.0",
              "results": [{
                "check_id": "C.ai.cve-monitoring.securecode.rules.kisa-insecure-random",
                "path": "src\\\\main\\\\A.java",
                "start": {"line": 3, "col": 24, "offset": 52},
                "end": {"line": 3, "col": 37, "offset": 65},
                "extra": {
                  "message": "예측 가능한 난수입니다.",
                  "severity": "WARNING",
                  "metadata": {"kisa_category": "보안기능", "kisa_name": "적절하지 않은 난수 값 사용", "cwe": "CWE-330"},
                  "lines": "requires login"
                }
              }],
              "errors": [
                {"code": 3, "level": "warn", "type": "Syntax error", "path": "src\\\\main\\\\Broken.java", "message": "x"},
                {"code": 7, "level": "error", "type": "Rule parse error", "message": "y"}
              ],
              "paths": {"scanned": ["src\\\\main\\\\A.java", "src\\\\main\\\\Broken.java"]}
            }
            """;

    @Test
    void 결과의_규칙id는_마지막_조각만_경로는_슬래시로() throws Exception {
        SemgrepReport report = parser.parse(JSON);

        assertThat(report.matches()).hasSize(1);
        SemgrepMatch match = report.matches().get(0);
        assertThat(match.ruleId()).isEqualTo("kisa-insecure-random");
        assertThat(match.filePath()).isEqualTo("src/main/A.java");
        assertThat(match.startLine()).isEqualTo(3);
        assertThat(match.endLine()).isEqualTo(3);
        assertThat(match.severity()).isEqualTo("MEDIUM");
        assertThat(match.kisaName()).isEqualTo("적절하지 않은 난수 값 사용");
        assertThat(match.cwe()).isEqualTo("CWE-330");
        assertThat(match.message()).isEqualTo("예측 가능한 난수입니다.");
    }

    @Test
    void Semgrep_심각도를_공통코드_심각도로_바꾼다() {
        assertThat(SemgrepReportParser.severity("ERROR")).isEqualTo("HIGH");
        assertThat(SemgrepReportParser.severity("WARNING")).isEqualTo("MEDIUM");
        assertThat(SemgrepReportParser.severity("INFO")).isEqualTo("LOW");
        assertThat(SemgrepReportParser.severity(null)).isNull();
    }

    @Test
    void 경로가_있는_오류만_분석실패_파일로_센다() throws Exception {
        SemgrepReport report = parser.parse(JSON);

        assertThat(report.failedFiles()).containsExactly("src/main/Broken.java");
        assertThat(report.scannedFileCount()).isEqualTo(2);
        assertThat(report.engineVersion()).isEqualTo("1.178.0");
    }

    @Test
    void 결과가_비어도_해석된다() throws Exception {
        SemgrepReport report = parser.parse("{\"results\":[],\"errors\":[],\"paths\":{\"scanned\":[]}}");

        assertThat(report.matches()).isEmpty();
        assertThat(report.failedFiles()).isEmpty();
        assertThat(report.scannedFileCount()).isZero();
    }
}
