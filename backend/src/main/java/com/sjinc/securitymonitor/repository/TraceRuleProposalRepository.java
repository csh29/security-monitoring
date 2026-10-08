package com.sjinc.securitymonitor.repository;

import com.sjinc.securitymonitor.domain.TraceRuleProposal;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface TraceRuleProposalRepository extends JpaRepository<TraceRuleProposal, Long> {

    /** 같은 변경의 가장 최근 기록 — 대기 중이면 묶고, 무시됐으면 다시 묻지 않는다. */
    Optional<TraceRuleProposal> findFirstByChangeKeyOrderByIdDesc(String changeKey);

    List<TraceRuleProposal> findByAppIdAndStatus(Long appId, String status);

    long countByStatus(String status);

    /** 최신순. status가 null이면 전체. */
    @Query("select p from TraceRuleProposal p where (:status is null or p.status = :status) order by p.lastSeenAt desc, p.id desc")
    List<TraceRuleProposal> findLatest(@Param("status") String status, Pageable pageable);
}
