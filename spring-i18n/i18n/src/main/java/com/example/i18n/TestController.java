package com.example.i18n;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


/**
 * Created by zk on 2018/10/10.
 */
@RestController
public class TestController {

    @Autowired
    private MessageSource messageSource;

    /**
     * 从代码获取
     *
     * @return
     */
    @RequestMapping("test1")
    public String test1() {
        return messageSource.getMessage("test1", new String[]{"替换的字符"}, LocaleContextHolder.getLocale());
    }
}
