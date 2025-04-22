package com.simpleoauth2server.GlobeAdvice.Exceptions;

public class PermissionDeniedException extends Exception{
    public PermissionDeniedException(String message){
        super(message);
    }
}
