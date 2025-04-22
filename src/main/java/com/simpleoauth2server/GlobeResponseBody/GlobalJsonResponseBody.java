package com.simpleoauth2server.GlobeResponseBody;

import lombok.Data;
import org.springframework.http.HttpStatus;

import java.util.Date;

@Data
public class GlobalJsonResponseBody {
    private Boolean success;
    private HttpStatus httpStatus;
    private String message;
    private Date action_time;
    private Object data;
}

