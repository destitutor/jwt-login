package kr.binarybard.jwtlogin.web.member.repository;

import kr.binarybard.jwtlogin.web.member.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findByEmail(String email);

    boolean existsByEmail(String email);

    default Member findByEmailOrThrow(String email) {
        return findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("해당 이메일이 존재하지 않습니다."));
    }
}
