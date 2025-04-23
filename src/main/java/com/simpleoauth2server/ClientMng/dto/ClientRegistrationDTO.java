package com.simpleoauth2server.ClientMng.dto;

import jakarta.persistence.Column;
import lombok.Data;

import java.util.Set;

@Data
public class ClientRegistrationDTO {

    private String clientId;

    private String clientName;

    private String authorizationGrantType;

    private String redirectUri;

    private boolean requireProofKey;

    private String tokenFormat;

}