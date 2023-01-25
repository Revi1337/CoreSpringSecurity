package com.example.corespringsecurity.domain.dto;

import lombok.*;

@Data
public class AccountDto {
    private String id;
    private String password;
    private String username;
    private String email;
    private int age;
    private String role;
}