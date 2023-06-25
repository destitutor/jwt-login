package kr.binarybard.jwtlogin.api.auth.repository;

import kr.binarybard.jwtlogin.api.auth.domain.RefreshToken;
import kr.binarybard.jwtlogin.web.member.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByMemberAndToken(Member member, String token);

    Long deleteByMember(Member member);
}
