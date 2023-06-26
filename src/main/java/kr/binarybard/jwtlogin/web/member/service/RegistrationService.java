package kr.binarybard.jwtlogin.web.member.service;

import jakarta.transaction.Transactional;
import kr.binarybard.jwtlogin.api.auth.dto.SignUpRequest;
import kr.binarybard.jwtlogin.common.exceptions.ErrorCode;
import kr.binarybard.jwtlogin.common.exceptions.InvalidValueException;
import kr.binarybard.jwtlogin.web.member.domain.Member;
import kr.binarybard.jwtlogin.web.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class RegistrationService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public Long save(SignUpRequest member) {
        validateDuplicateEmail(member.getEmail());
        var newMember = new Member(member.getEmail(), member.getPassword());
        newMember.encodePassword(passwordEncoder);
        return memberRepository.save(newMember).getId();
    }

    private void validateDuplicateEmail(String email) {
        if (memberRepository.existsByEmail(email)) {
            throw new InvalidValueException(ErrorCode.DUPLICATED_EMAIL);
        }
    }
}
