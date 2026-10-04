package vn.iotstar.exceptions;

public class InvalidJwtException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public InvalidJwtException(String message) {
        super(message);
    }

    public InvalidJwtException(String message, Throwable cause) {
        super(message, cause);
    }
}