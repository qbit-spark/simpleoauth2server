package com.simpleoauth2server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SimpleOauth2ServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(SimpleOauth2ServerApplication.class, args);
    }

}


/***
 *  If you wan tto generate keys for JWT
 */
//public static void main(String[] args) throws Exception {
//    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//    keyPairGenerator.initialize(2048);
//    KeyPair keyPair = keyPairGenerator.generateKeyPair();
//
//    String publicKeyString = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
//    String privateKeyString = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
//
//    System.out.println("Public Key: " + publicKeyString);
//    System.out.println("Private Key: " + privateKeyString);
//}