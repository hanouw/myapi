package com.cicd.myapi.repository;

import com.cicd.myapi.domain.Member;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface MemberRepository  extends JpaRepository<Member, String> {

    // 회원 조회 + 롤 목록 포함 = select 한번만 실행해 두 개 테이블 내용 가져오기 위해 @EntityGraph 사용
    @EntityGraph(attributePaths = {"roleList"}) // 조인해서 한번에 호출
    @Query("select m from Member m where m.email =:email")
    Member getMemberWithRoles(@Param("email") String email);
}
