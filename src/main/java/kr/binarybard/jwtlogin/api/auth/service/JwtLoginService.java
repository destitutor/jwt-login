package kr.binarybard.jwtlogin.api.auth.service;

import kr.binarybard.jwtlogin.api.auth.dto.RefreshTokenRequest;
import kr.binarybard.jwtlogin.api.auth.dto.SignInRequest;
import kr.binarybard.jwtlogin.api.auth.dto.TokenResponse;
import kr.binarybard.jwtlogin.common.exceptions.AuthenticationException;
import kr.binarybard.jwtlogin.common.exceptions.ErrorCode;
import kr.binarybard.jwtlogin.config.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JwtLoginService {
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final RefreshTokenService refreshTokenService;
    private final JwtTokenProvider tokenProvider;

    public TokenResponse authenticateUser(SignInRequest request) {
        var authenticationToken = new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword());
        var authentication = authenticationManagerBuilder.getObject()
                .authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return generateJwtTokens(request.getEmail(), authentication);
    }

    public TokenResponse refreshJwtTokens(RefreshTokenRequest request) {
        String currentRefreshToken = request.getRefreshToken();
        validateRefreshToken(currentRefreshToken);
        var authentication = tokenProvider.getAuthentication(currentRefreshToken);
        return generateJwtTokens(authentication.getName(), authentication);
    }

    private TokenResponse generateJwtTokens(String username, Authentication authentication) {
        String accessToken = tokenProvider.createAccessToken(authentication);
        String refreshToken = createAndSaveRefreshToken(username, authentication);
        return new TokenResponse(accessToken, refreshToken);
    }

    private String createAndSaveRefreshToken(String email, Authentication authentication) {
        String refreshToken = tokenProvider.createRefreshToken(authentication);

        refreshTokenService.deleteTokenByEmail(email);
        refreshTokenService.save(email, refreshToken);

        return refreshToken;
    }

    private void validateRefreshToken(String token) {
        if (!refreshTokenService.validateToken(token)) {
            throw new AuthenticationException(ErrorCode.INVALID_TOKEN);
        }
    }
}
