package kr.binarybard.jwtlogin.web.member.service;

import jakarta.transaction.Transactional;
import kr.binarybard.jwtlogin.api.auth.dto.SignUpRequest;
import kr.binarybard.jwtlogin.common.exceptions.ErrorCode;
import kr.binarybard.jwtlogin.common.exceptions.InvalidValueException;
import kr.binarybard.jwtlogin.web.member.domain.Member;
import kr.binarybard.jwtlogin.web.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class MemberService implements UserDetailsService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var member = memberRepository.findByEmail(username)
            .orElseThrow(() -> new UsernameNotFoundException(username));
        return User.builder()
                .username(member.getEmail())
                .password(member.getPassword())
                .build();
    }

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
