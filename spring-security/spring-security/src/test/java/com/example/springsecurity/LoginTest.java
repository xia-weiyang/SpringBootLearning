package com.example.springsecurity;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * Created by zk on 2018/8/7.
 */
@RunWith(SpringRunner.class)
@SpringBootTest
public class LoginTest {

    private final TestRestTemplate restTemplate;

    public LoginTest(TestRestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Test
    public void loginTest(){
    }
}
