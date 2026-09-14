package com.sjinc.cvemonitor.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {

    @Bean
    public WebClient nvdWebClient(@Value("${nvd.api.key}") String apiKey) {
        return WebClient.builder()
                .baseUrl("https://services.nvd.nist.gov/rest/json/cves/2.0")
                .defaultHeader("apiKey", apiKey)
                .build();
    }

    @Bean
    public WebClient osvWebClient(WebClient.Builder builder) {
        return builder.baseUrl("https://api.osv.dev").build();
    }

    @Bean
    public WebClient mavenCentralWebClient(WebClient.Builder builder) {
        return builder.baseUrl("https://repo1.maven.org/maven2").build();
    }
}
