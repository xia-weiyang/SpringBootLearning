package com.example.springsecurity;

import com.example.springsecurity.service.UserDetailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

@RestController
@SpringBootApplication
public class SpringSecurityApplication {

    private Logger logger = LoggerFactory.getLogger(SpringSecurityApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);
    }

    // 装载BCrypt密码编码器
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @RequestMapping("test")
    public String test() {
        return "test";
    }

    @RequestMapping(value = "user/login", method = RequestMethod.GET)
    public String login() {
        return "login";
    }


    @RequestMapping(value = "login", method = RequestMethod.POST)
    public String login1() {
        return "success";
    }

    @Configuration
    @EnableWebSecurity
    public static class SecurityConfig extends WebSecurityConfigurerAdapter {
        private final UserDetailService userDetailService;
        private final PasswordEncoder passwordEncoder;

        public SecurityConfig(UserDetailService userDetailService, PasswordEncoder passwordEncoder) {
            this.userDetailService = userDetailService;
            this.passwordEncoder = passwordEncoder;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.cors().and().csrf().disable().authorizeRequests()
                    .anyRequest()
                    .authenticated()
                    .and()
//                    .formLogin()   禁用登陆页面
//                    .and()
                    .addFilter(new UserLoginFilter(authenticationManager()))
                    .addFilter(new AuthenticationFilter(authenticationManager()));
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.userDetailsService(userDetailService).passwordEncoder(passwordEncoder);
        }

    }

    /**
     * 登陆拦截
     */
    public static class UserLoginFilter extends UsernamePasswordAuthenticationFilter {

        private AuthenticationManager authenticationManager;

        public UserLoginFilter(AuthenticationManager authenticationManager) {
            this.authenticationManager = authenticationManager;
        }

        // 接收并解析用户凭证
        @Override
        public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
            String username = request.getParameter("account");
            String password = request.getParameter("password");
            logger.info(username + "  " + password);
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            username, password,
                            new ArrayList<>())
            );
        }

        @Override
        protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
            logger.info("登陆验证成功");
//            response.setStatus(200);  // 当禁用登陆页面时，设置返回状态吗为200
            response.getWriter().append(authResult.getPrincipal().toString()).flush();
//            super.successfulAuthentication(request, response, chain, authResult);
        }

        @Override
        protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
            logger.info("登陆验证失败");
            logger.info(failed.getMessage());
            super.unsuccessfulAuthentication(request, response, failed);
        }
    }

    public static class AuthenticationFilter extends BasicAuthenticationFilter {
        public AuthenticationFilter(AuthenticationManager authenticationManager) {
            super(authenticationManager);
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
            chain.doFilter(request, response);
        }
    }
}
