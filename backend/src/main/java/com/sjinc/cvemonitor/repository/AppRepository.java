package com.sjinc.cvemonitor.repository;

import com.sjinc.cvemonitor.domain.App;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AppRepository extends JpaRepository<App, Long> {

    List<App> findAllByOrderByIdAsc();

    Optional<App> findByRepoUrlAndBranch(String repoUrl, String branch);
}
