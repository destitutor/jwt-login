package kr.binarybard.jwtlogin.common.exceptions;

public class InvalidValueException extends ApplicationException {
    public InvalidValueException(ErrorCode errorCode) {
        super(errorCode);
    }

    public InvalidValueException(ErrorCode errorCode, String detail) {
        super(errorCode, detail);
    }
}