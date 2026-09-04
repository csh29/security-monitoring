package com.sjinc.cvemonitor.dto.nvd;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * CVE 설명 텍스트 하나를 언어별로 표현하는 DTO.
 *
 * <p>NVD는 하나의 CVE에 대해 여러 언어(en, es 등)의 설명을 배열로 제공한다.
 * 예: {@code { "lang": "en", "value": "A vulnerability in ..." }}
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Description {

    /** 설명의 언어 코드. 예: "en", "es". 시스템에서는 "en"만 사용. */
    private String lang;

    /** 실제 취약점 설명 본문. */
    private String value;

    public String getLang() { return lang; }
    public void setLang(String lang) { this.lang = lang; }
    public String getValue() { return value; }
    public void setValue(String value) { this.value = value; }
}