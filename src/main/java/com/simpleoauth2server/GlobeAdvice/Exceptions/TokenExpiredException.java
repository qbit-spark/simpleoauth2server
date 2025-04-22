package com.simpleoauth2server.GlobeAdvice.Exceptions;

public class TokenExpiredException extends Exception{
    public TokenExpiredException(String message){
        super(message);
    }
}
