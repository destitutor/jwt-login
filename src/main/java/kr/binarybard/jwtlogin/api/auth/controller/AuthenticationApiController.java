package kr.binarybard.jwtlogin.api.auth.controller;

import jakarta.validation.Valid;
import kr.binarybard.jwtlogin.api.auth.dto.RefreshTokenRequest;
import kr.binarybard.jwtlogin.api.auth.dto.SignInRequest;
import kr.binarybard.jwtlogin.api.auth.dto.SignUpRequest;
import kr.binarybard.jwtlogin.api.auth.dto.TokenResponse;
import kr.binarybard.jwtlogin.api.auth.service.JwtLoginService;
import kr.binarybard.jwtlogin.web.member.service.RegistrationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationApiController {
    private final RegistrationService memberService;
    private final JwtLoginService loginService;

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> authorize(@Valid @RequestBody SignInRequest request) {
        return ResponseEntity.ok().body(loginService.authenticateUser(request));
    }

    @PostMapping("/reissue")
    public ResponseEntity<TokenResponse> reissue(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok().body(loginService.refreshJwtTokens(request));
    }

    @PostMapping("/signup")
    public ResponseEntity<Void> registerUser(@Valid @RequestBody SignUpRequest request) {
        Long savedId = memberService.save(request);
        return ResponseEntity.created(URI.create("/api/members/" + savedId)).build();
    }
}
