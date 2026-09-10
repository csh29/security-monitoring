package com.sjinc.cvemonitor.repository;

import com.sjinc.cvemonitor.domain.Program;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ProgramRepository extends JpaRepository<Program, String> {

    List<Program> findAllByOrderBySortOrderAsc();
}
