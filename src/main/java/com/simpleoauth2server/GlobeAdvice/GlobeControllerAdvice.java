package com.simpleoauth2server.GlobeAdvice;

import com.simpleoauth2server.GlobeAdvice.Exceptions.*;
import com.simpleoauth2server.GlobeResponseBody.GlobalJsonResponseBody;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class GlobeControllerAdvice {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<GlobalJsonResponseBody> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        // Create a new instance of GlobalJsonResponseBody
        GlobalJsonResponseBody responseBody = new GlobalJsonResponseBody();
        responseBody.setSuccess(false);
        responseBody.setHttpStatus(HttpStatus.UNPROCESSABLE_ENTITY);
        responseBody.setMessage("Validation failed");
        responseBody.setAction_time(new Date());
        responseBody.setData(errors); // Set the validation errors as the data

        // Return the response entity with the custom body and HTTP status
        return new ResponseEntity<>(responseBody, HttpStatus.UNPROCESSABLE_ENTITY);
    }



    @ExceptionHandler(TokenEmptyException.class)
    public ResponseEntity<GlobalJsonResponseBody> generateTokenEmptyException(Exception exception) {

        GlobalJsonResponseBody globalJsonResponseBody = getGlobalJsonResponseBody(exception, HttpStatus.UNAUTHORIZED);

        return new ResponseEntity<>(globalJsonResponseBody, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(TokenInvalidException.class)
    public ResponseEntity<GlobalJsonResponseBody> generateInvalidTokenException(Exception exception) {

        GlobalJsonResponseBody globalJsonResponseBody = getGlobalJsonResponseBody(exception, HttpStatus.UNAUTHORIZED);

        return new ResponseEntity<>(globalJsonResponseBody, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<GlobalJsonResponseBody> generateTokenExpirationException(Exception exception) {

        GlobalJsonResponseBody globalJsonResponseBody = getGlobalJsonResponseBody(exception, HttpStatus.UNAUTHORIZED);

        return new ResponseEntity<>(globalJsonResponseBody, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(TokenInvalidSignatureException.class)
    public ResponseEntity<GlobalJsonResponseBody> generateTokenInvalidSignatureException(Exception exception) {

        GlobalJsonResponseBody globalJsonResponseBody = getGlobalJsonResponseBody(exception, HttpStatus.UNAUTHORIZED);

        return new ResponseEntity<>(globalJsonResponseBody, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(TokenUnsupportedException.class)
    public ResponseEntity<GlobalJsonResponseBody> generateTokenUnsupportedException(Exception exception) {

        GlobalJsonResponseBody globalJsonResponseBody = getGlobalJsonResponseBody(exception, HttpStatus.UNAUTHORIZED);

        return new ResponseEntity<>(globalJsonResponseBody, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(UserExistException.class)
    public ResponseEntity<GlobalJsonResponseBody> generateUserExistException(Exception exception) {

        GlobalJsonResponseBody globalJsonResponseBody = getGlobalJsonResponseBody(exception, HttpStatus.CONFLICT);

        return new ResponseEntity<>(globalJsonResponseBody, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(VerificationException.class)
    public ResponseEntity<GlobalJsonResponseBody> getVerificationException(Exception exception) {

        GlobalJsonResponseBody globalJsonResponseBody = getGlobalJsonResponseBody(exception, HttpStatus.FORBIDDEN);

        return new ResponseEntity<>(globalJsonResponseBody, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(RandomExceptions.class)
    public ResponseEntity<GlobalJsonResponseBody> getRandomExceptions(Exception exception) {

        GlobalJsonResponseBody globalJsonResponseBody = getGlobalJsonResponseBody(exception, HttpStatus.BAD_REQUEST);

        return new ResponseEntity<>(globalJsonResponseBody, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(ItemReadyExistException.class)
    public ResponseEntity<GlobalJsonResponseBody> itemReadyExist(Exception exception) {

        GlobalJsonResponseBody globalJsonResponseBody = getGlobalJsonResponseBody(exception, HttpStatus.BAD_REQUEST);

        return new ResponseEntity<>(globalJsonResponseBody, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<GlobalJsonResponseBody> handleAllExceptions(Exception exception) {
        GlobalJsonResponseBody globalJsonResponseBody = getGlobalJsonResponseBodyAllExp(exception, HttpStatus.BAD_REQUEST);
        return new ResponseEntity<>(globalJsonResponseBody, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<GlobalJsonResponseBody> generateAccessDeniedExceptionException(Exception exception) {

        GlobalJsonResponseBody globalJsonResponseBody = getGlobalJsonResponseBody(exception, HttpStatus.BAD_REQUEST);

        return new ResponseEntity<>(globalJsonResponseBody, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(PermissionDeniedException.class)
    public ResponseEntity<GlobalJsonResponseBody> generatePermissionDeniedException(Exception exception) {

        GlobalJsonResponseBody globalJsonResponseBody = getGlobalJsonResponseBody(exception, HttpStatus.FORBIDDEN);

        return new ResponseEntity<>(globalJsonResponseBody, HttpStatus.FORBIDDEN);
    }

    private static GlobalJsonResponseBody getGlobalJsonResponseBody(Exception exception, HttpStatus status) {
        GlobalJsonResponseBody globalJsonResponseBody = new GlobalJsonResponseBody();
        globalJsonResponseBody.setMessage(exception.getMessage());
        globalJsonResponseBody.setData(exception.getMessage());
        globalJsonResponseBody.setSuccess(false);
        globalJsonResponseBody.setAction_time(new Date());
        globalJsonResponseBody.setHttpStatus(status);
        return globalJsonResponseBody;
    }


    private static GlobalJsonResponseBody getGlobalJsonResponseBodyAllExp(Exception exception, HttpStatus status) {

        // Extract the original exception message
        String message = exception.getMessage();
        String trimmedMessage;

        // Handle specific cases with detailed error messages
        if (message.contains("is not available yet")) {
            // For daily special visibility errors, retain the full message
            trimmedMessage = message;
        } else if (message.contains(":")) {
            // For other cases with colons, trim at the colon
            trimmedMessage = message.split(":")[0].trim();
        } else {
            // Use the full message if no special handling is required
            trimmedMessage = message;
        }

        // Construct the response body
        GlobalJsonResponseBody globalJsonResponseBody = new GlobalJsonResponseBody();
        globalJsonResponseBody.setMessage(trimmedMessage);
        globalJsonResponseBody.setData(trimmedMessage);
        globalJsonResponseBody.setSuccess(false);
        globalJsonResponseBody.setAction_time(new Date());
        globalJsonResponseBody.setHttpStatus(status);
        return globalJsonResponseBody;
    }


}
