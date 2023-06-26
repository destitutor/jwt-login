package kr.binarybard.jwtlogin.api.auth.controller;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import kr.binarybard.jwtlogin.api.auth.dto.RefreshTokenRequest;
import kr.binarybard.jwtlogin.api.auth.dto.SignInRequest;
import kr.binarybard.jwtlogin.api.auth.dto.SignUpRequest;
import kr.binarybard.jwtlogin.api.auth.service.RefreshTokenService;
import kr.binarybard.jwtlogin.common.exceptions.AuthenticationException;
import kr.binarybard.jwtlogin.common.exceptions.ErrorCode;
import kr.binarybard.jwtlogin.config.jwt.JwtTokenProvider;
import kr.binarybard.jwtlogin.web.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationApiController {
    private final JwtTokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final MemberService memberService;
    private final RefreshTokenService refreshTokenService;

    @PostMapping("/login")
    public ResponseEntity<JwtTokens> authorize(@Valid @RequestBody SignInRequest request) {
        var authenticationToken = new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword());
        var authentication = authenticationManagerBuilder.getObject()
                .authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return ResponseEntity.ok().body(generateJwtTokens(request.getEmail(), authentication));
    }

    @PostMapping("/reissue")
    public ResponseEntity<JwtTokens> reissue(@Valid @RequestBody RefreshTokenRequest request) {
        String currentRefreshToken = request.getRefreshToken();
        validateRefreshToken(currentRefreshToken);
        var authentication = tokenProvider.getAuthentication(currentRefreshToken);
        return ResponseEntity.ok().body(generateJwtTokens(authentication.getName(), authentication));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest request) {
        Long savedId = memberService.save(request);
        return ResponseEntity.created(URI.create("/api/members/" + savedId)).build();
    }

    private JwtTokens generateJwtTokens(String username, Authentication authentication) {
        String accessToken = tokenProvider.createAccessToken(authentication);
        String refreshToken = createAndSaveRefreshToken(username, authentication);

        return new JwtTokens(accessToken, refreshToken);
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

    private record JwtTokens(@JsonProperty("access_token") String accessToken,
                             @JsonProperty("refresh_token") String refreshToken) {
    }
}
