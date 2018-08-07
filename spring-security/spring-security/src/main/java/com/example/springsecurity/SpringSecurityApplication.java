package com.example.springsecurity;

import com.example.springsecurity.po.UserDetail;
import com.example.springsecurity.service.UserDetailService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
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
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

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
                    .antMatchers("/user/login").permitAll()  // 允许该接口访问
                    .anyRequest()
                    .authenticated()
                    .and()
//                    .formLogin()   禁用登陆页面
//                    .and()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // 禁用session
                    .and()
                    .addFilter(new UserLoginFilter(authenticationManager()))
                    .addFilter(new AuthenticationFilter(authenticationManager()));
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.userDetailsService(userDetailService).passwordEncoder(passwordEncoder);
        }

        @Bean
        public AuthenticationManager getAuthenticationManager() throws Exception {
            return authenticationManager();
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
//            super.successfulAuthentication(request, response, chain, authResult);
            // 添加token
            String token = Jwts.builder()
                    .setSubject(((UserDetail) authResult.getPrincipal()).getUsername())
                    .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 24 * 1000))
                    .signWith(SignatureAlgorithm.HS512, "MyJwtSecret")
                    .compact();
            response.addHeader("Authorization", "Bearer " + token);
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
            logger.info("验证请求是否合法");
            String header = request.getHeader("Authorization");

            if (header == null || !header.startsWith("Bearer ")) {
                chain.doFilter(request, response);
                return;
            }

            UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);

        }

        private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
            String token = request.getHeader("Authorization");
            if (token != null) {
                // parse the token.
                String user = Jwts.parser()
                        .setSigningKey("MyJwtSecret")
                        .parseClaimsJws(token.replace("Bearer ", ""))
                        .getBody()
                        .getSubject();

                if (user != null) {
                    return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
                }
                return null;
            }
            return null;
        }
    }
}
