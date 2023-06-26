package kr.binarybard.jwtlogin.api.auth.service;

import jakarta.transaction.Transactional;
import kr.binarybard.jwtlogin.common.exceptions.ErrorCode;
import kr.binarybard.jwtlogin.common.exceptions.InvalidValueException;
import kr.binarybard.jwtlogin.config.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RedisTemplate<String, String> redisTemplate;
    private final JwtTokenProvider tokenProvider;

    @Transactional
    public void deleteTokenByEmail(String email) {
        redisTemplate.delete(email);
    }

    public void save(String email, String token) {
        redisTemplate.opsForValue().set(email, hashToken(token), tokenProvider.REFRESH_TOKEN_EXPIRE_TIME, TimeUnit.MILLISECONDS);
    }

    public boolean validateToken(String token) {
        if (!tokenProvider.validateToken(token)) {
            return false;
        }

        String hashedToken = redisTemplate.opsForValue().get(tokenProvider.getUsernameFromToken(token));
        return hashedToken != null && hashedToken.equals(hashToken(token));
    }

    private String hashToken(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException ignored) {
            /* SHA-256 is always available */
            return "";
        }
    }
}
