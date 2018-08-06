package com.example.springsecurity.service;

import com.example.springsecurity.po.UserDetail;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Created by zk on 2018/8/6.
 */
@Service
public class UserDetailService implements UserDetailsService {

    private final Logger logger = LoggerFactory.getLogger(UserDetailService.class);

    private final PasswordEncoder passwordEncoder;

    public UserDetailService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.info("username:" + username);
        return new UserDetail(username, passwordEncoder.encode("111111"));
    }
}
