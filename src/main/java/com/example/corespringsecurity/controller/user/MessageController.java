package com.example.corespringsecurity.controller.user;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MessageController {

    @GetMapping(value = "/messages")
    public String myPage() throws Exception {

        return "user/messages";
    }

    @GetMapping("/api/messages")
    @ResponseBody
    public String apiMessage() {
        return "message ok";
    }
}
