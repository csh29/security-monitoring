package com.sjinc.cvemonitor.repository;

import com.sjinc.cvemonitor.domain.CommonCodeGroup;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CommonCodeGroupRepository extends JpaRepository<CommonCodeGroup, String> {

    List<CommonCodeGroup> findAllByOrderBySortOrderAsc();
}
