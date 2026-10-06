package com.sjinc.securitymonitor.repository;

import com.sjinc.securitymonitor.domain.Program;
import com.sjinc.securitymonitor.domain.UserProgramPermission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface UserProgramPermissionRepository extends JpaRepository<UserProgramPermission, Long> {

    @Query("select perm.program from UserProgramPermission perm "
            + "where perm.user.username = :username "
            + "and perm.program.useYn = 'Y' "
            + "order by perm.program.sortOrder asc")
    List<Program> findAccessiblePrograms(@Param("username") String username);

    List<UserProgramPermission> findByUserId(Long userId);

    /** 화면 툴바 버튼을 정할 때 쓴다 — 그 사용자의 그 프로그램 권한 행(없으면 접근 권한도 없음). */
    Optional<UserProgramPermission> findByUserUsernameAndProgramProgramId(String username, String programId);

    /**
     * 벌크 DELETE로 즉시 실행된다(엔티티 삭제 큐잉과 달리 flush를 기다리지 않음).
     * 같은 트랜잭션에서 곧이어 동일 (user_id, program_id)를 다시 insert해야 하는
     * 권한 재설정 시나리오에서, Hibernate가 삭제보다 삽입을 먼저 flush해
     * unique 제약을 위반하는 문제를 피하기 위해 사용한다.
     */
    @Modifying(clearAutomatically = true)
    @Query("delete from UserProgramPermission perm where perm.user.id = :userId")
    void deleteByUserId(@Param("userId") Long userId);
}
