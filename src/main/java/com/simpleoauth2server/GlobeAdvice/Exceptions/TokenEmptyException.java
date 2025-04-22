package com.simpleoauth2server.GlobeAdvice.Exceptions;

public class TokenEmptyException extends Exception{
    public TokenEmptyException(String message){
        super(message);
    }
}
