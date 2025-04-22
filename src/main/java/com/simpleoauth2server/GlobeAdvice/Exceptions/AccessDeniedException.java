package com.simpleoauth2server.GlobeAdvice.Exceptions;

public class AccessDeniedException extends Exception{
    public AccessDeniedException(String message){
        super(message);
    }
}
