package com.example.corespringsecurity.security;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity @RequiredArgsConstructor
public class SecurityConfig {

    private final FormWebAuthenticationDetailsSource formWebAuthenticationDetailsSource;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .authorizeHttpRequests(auth -> auth
                        .mvcMatchers("/", "/users", "user/login/**").permitAll()
                        .mvcMatchers("/mypage").hasRole("USER")
                        .mvcMatchers("/messages").hasRole("MANAGER")
                        .mvcMatchers("/config").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/")
                        .loginProcessingUrl("/login_proc")
                        .authenticationDetailsSource(formWebAuthenticationDetailsSource)
                        .permitAll())
                .build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web
                .ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }
}

//    private final CustomUserDetailsService customUserDetailsService;
//    /**
//     * <p>Used for Register CustomUserDetailsService</p>
//     * @return {@link AuthenticationManager}
//     */
//    @Bean
//    public AuthenticationManager authenticationManager() {
//        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
//        daoAuthenticationProvider.setUserDetailsService(customUserDetailsService);
//    }
