package com.simpleoauth2server.Config.CorsConfig;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;


//Bro we got another shit here never sniff here.........
@Configuration
public class WebConfig implements WebMvcConfigurer {


    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("*") // Allow all origins for testing; restrict in production
                .allowedMethods("*")
                .allowedHeaders("*")
                .allowCredentials(false); // Set to true if using cookies or HTTP authentication
    }
}

