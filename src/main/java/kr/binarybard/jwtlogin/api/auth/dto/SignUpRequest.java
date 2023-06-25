package kr.binarybard.jwtlogin.api.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import kr.binarybard.jwtlogin.common.validator.PasswordConstraint;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.Length;

@Getter
@Setter
public class SignUpRequest {
    @NotEmpty
    @Email
    @Length(max = 32)
    private String email;

    @PasswordConstraint
    private String password;

    @Builder
    public SignUpRequest(String email, String password) {
        this.email = email;
        this.password = password;
    }
}
