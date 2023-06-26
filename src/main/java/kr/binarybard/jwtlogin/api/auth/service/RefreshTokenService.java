package kr.binarybard.jwtlogin.api.auth.service;

import jakarta.transaction.Transactional;
import kr.binarybard.jwtlogin.api.auth.domain.RefreshToken;
import kr.binarybard.jwtlogin.api.auth.repository.RefreshTokenRepository;
import kr.binarybard.jwtlogin.common.exceptions.ErrorCode;
import kr.binarybard.jwtlogin.common.exceptions.InvalidValueException;
import kr.binarybard.jwtlogin.config.jwt.JwtTokenProvider;
import kr.binarybard.jwtlogin.web.member.domain.Member;
import kr.binarybard.jwtlogin.web.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider tokenProvider;
    private final MemberRepository memberRepository;

    @Transactional
    public void deleteTokenByEmail(String email) {
        refreshTokenRepository.deleteByMember(memberRepository.findByEmailOrThrow(email));
    }

    @Transactional
    public Long save(String email, String token) {
        var refreshToken = RefreshToken.builder()
                .member(memberRepository.findByEmailOrThrow(email))
                .token(hashToken(token))
                .expiryDate(Instant.now().plusMillis(tokenProvider.REFRESH_TOKEN_EXPIRE_TIME))
                .build();
        return refreshTokenRepository.save(refreshToken).getId();
    }

    private String hashToken(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidValueException(ErrorCode.TOKEN_HASHING_ERROR);
        }
    }

    public boolean validateToken(String token) {
        if (!tokenProvider.validateToken(token)) {
            return false;
        }

        Optional<RefreshToken> storedRefreshToken = getStoredRefreshToken(token);
        return storedRefreshToken.isPresent() && isTokenNotExpired(storedRefreshToken.get());
    }

    private Optional<RefreshToken> getStoredRefreshToken(String token) {
        String username = tokenProvider.getUsernameFromToken(token);
        Member member = memberRepository.findByEmailOrThrow(username);
        return refreshTokenRepository.findByMemberAndToken(member, hashToken(token));
    }

    private boolean isTokenNotExpired(RefreshToken token) {
        return !token.getExpiryDate().isBefore(Instant.now());
    }
}
