package com.example.adminClient;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@SpringBootApplication
public class AdminClientApplication {
    private final static Logger logger = LoggerFactory.getLogger(AdminClientApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(AdminClientApplication.class, args);

        logger.info("info");
    }

    @RequestMapping("test")
    public String test() {
        logger.debug("debug");
        logger.info("info");
        logger.warn("warn");
        logger.error("error");
        return "test";
    }

    // 非安全模式下所有暴露所有接口
//    @Configuration
//    public static class SecurityPermitAllConfig extends WebSecurityConfigurerAdapter {
//        @Override
//        protected void configure(HttpSecurity http) throws Exception {
//            http.authorizeRequests().anyRequest().permitAll()
//                    .and().csrf().disable();
//        }
//    }
}
