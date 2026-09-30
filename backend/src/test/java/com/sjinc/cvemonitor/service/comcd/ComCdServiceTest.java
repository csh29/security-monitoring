package com.sjinc.cvemonitor.service.comcd;

import com.sjinc.cvemonitor.domain.ComCd;
import com.sjinc.cvemonitor.repository.ComCdRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ComCdServiceTest {

    private ComCdRepository comCdRepository;
    private ComCdService service;

    @BeforeEach
    void setUp() {
        comCdRepository = mock(ComCdRepository.class);
        service = new ComCdService(comCdRepository);
    }

    private void givenCode(String useYn) {
        when(comCdRepository.findFirstByCodeGroupAndCodeValueOrderByIdAsc("AI_CONFIG", "AUTO_TRIGGER"))
                .thenReturn(Optional.of(ComCd.builder().codeGroup("AI_CONFIG").codeValue("AUTO_TRIGGER").useYn(useYn).build()));
    }

    @Test
    void 사용여부가_Y면_켜짐이고_N이면_꺼짐이다() {
        givenCode("Y");
        assertThat(service.isEnabled("AI_CONFIG", "AUTO_TRIGGER", false)).isTrue();

        givenCode("N");
        assertThat(service.isEnabled("AI_CONFIG", "AUTO_TRIGGER", true)).isFalse();
    }

    @Test
    void 코드가_없으면_기본값을_쓴다() {
        when(comCdRepository.findFirstByCodeGroupAndCodeValueOrderByIdAsc("AI_CONFIG", "AUTO_TRIGGER"))
                .thenReturn(Optional.empty());

        assertThat(service.isEnabled("AI_CONFIG", "AUTO_TRIGGER", true)).isTrue();
        assertThat(service.isEnabled("AI_CONFIG", "AUTO_TRIGGER", false)).isFalse();
    }
}
