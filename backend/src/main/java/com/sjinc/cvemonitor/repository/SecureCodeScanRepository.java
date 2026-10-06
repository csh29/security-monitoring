package com.sjinc.cvemonitor.repository;

import com.sjinc.cvemonitor.domain.SecureCodeScan;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface SecureCodeScanRepository extends JpaRepository<SecureCodeScan, Long> {

    /** 최신순. appId가 null이면 전체 앱. */
    @Query("select s from SecureCodeScan s where (:appId is null or s.appId = :appId) "
            + "order by s.startedAt desc, s.id desc")
    List<SecureCodeScan> findLatest(@Param("appId") Long appId, Pageable pageable);
}
