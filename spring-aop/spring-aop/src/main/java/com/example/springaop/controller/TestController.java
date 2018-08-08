package com.example.springaop.controller;

import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by zk on 2018/8/8.
 */
@RestController
public class TestController {

    @RequestMapping("query")
    public String query(String params) {
        return params;
    }


    @RequestMapping(value = "body",method = RequestMethod.POST)
    public String body(@RequestBody String text) {
        return text;
    }
}
