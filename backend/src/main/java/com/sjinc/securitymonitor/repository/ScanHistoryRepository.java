package com.sjinc.securitymonitor.repository;

import com.sjinc.securitymonitor.domain.ScanHistory;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ScanHistoryRepository extends JpaRepository<ScanHistory, Long> {

    /** 최신순. appId가 null이면 전체 앱. */
    @Query("select h from ScanHistory h where (:appId is null or h.appId = :appId) "
            + "order by h.startedAt desc, h.id desc")
    List<ScanHistory> findLatest(@Param("appId") Long appId, Pageable pageable);
}
