package com.simpleoauth2server;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

@SpringBootApplication
public class SimpleOauth2ServerApplication implements CommandLineRunner {

    public static void main(String[] args) {
        SpringApplication.run(SimpleOauth2ServerApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        //generateKeys();
    }

    /***
     *  If you want to generate keys for JWT
     */
     void generateKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        String publicKeyString = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        String privateKeyString = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

        System.out.println("app.security.rsa.public-key=" + publicKeyString);
        System.out.println("app.security.rsa.private-key=" + privateKeyString);
    }
}


