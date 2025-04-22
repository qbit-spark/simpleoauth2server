package com.simpleoauth2server.GlobeAdvice.Exceptions;

public class TokenInvalidSignatureException extends Exception{
    public TokenInvalidSignatureException(String message){
        super(message);
    }
}
