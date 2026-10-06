package com.sjinc.securitymonitor.repository;

import com.sjinc.securitymonitor.domain.Program;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface ProgramRepository extends JpaRepository<Program, String> {

    @Query("select p from Program p order by p.sortOrder asc")
    List<Program> findAllSorted();
}
