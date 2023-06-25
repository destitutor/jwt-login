package kr.binarybard.jwtlogin.common.exceptions;

import lombok.Getter;

@Getter
public class ApplicationException extends RuntimeException {
    private final String detail;
    private final ErrorCode errorCode;

    public ApplicationException(ErrorCode errorCode, String detail) {
        super(errorCode.getMessage() + (detail == null ? "" : " (" + detail + ")"));
        this.errorCode = errorCode;
        this.detail = detail;
    }

    public ApplicationException(ErrorCode errorCode) {
        this(errorCode, null);
    }
}
