package kr.binarybard.jwtlogin.common.exceptions;

public class AuthenticationException extends ApplicationException {

    public AuthenticationException(ErrorCode errorCode, String detail) {
        super(errorCode, detail);
    }

    public AuthenticationException(ErrorCode errorCode) {
        super(errorCode);
    }
}
