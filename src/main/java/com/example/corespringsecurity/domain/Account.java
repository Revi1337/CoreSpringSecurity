package com.example.corespringsecurity.domain;

import lombok.*;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.io.Serializable;

@Entity @NoArgsConstructor @AllArgsConstructor @Getter  @ToString
public class Account implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private Long id;

    @Setter private String username;

    @Setter private String password;

    @Setter private String email;

    @Setter private String age;

    @Setter private String role;

}
