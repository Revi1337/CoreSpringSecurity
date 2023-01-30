package com.example.corespringsecurity.controller.user;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MessageController {

    @GetMapping(value = "/messages")
    public String myPage() throws Exception {

        return "user/messages";
    }

    @PostMapping("/api/messages")
    @ResponseBody
    public ResponseEntity<String> apiMessage() throws Exception{
        return ResponseEntity.ok().body("ok");
    }
}
