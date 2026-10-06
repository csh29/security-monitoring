package com.sjinc.securitymonitor.repository;

import com.sjinc.securitymonitor.domain.ComCdGroup;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ComCdGroupRepository extends JpaRepository<ComCdGroup, String> {

    List<ComCdGroup> findAllByOrderBySortOrderAsc();
}
