package com.simpleoauth2server.GlobeAdvice.Exceptions;

public class TokenInvalidException extends Exception{
    public TokenInvalidException(String message){
        super(message);
    }
}
