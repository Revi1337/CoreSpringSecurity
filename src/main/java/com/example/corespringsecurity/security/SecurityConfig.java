package com.example.corespringsecurity.security;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity @RequiredArgsConstructor
public class SecurityConfig {
    
    private final CustomUserDetailsService customUserDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(customUserDetailsService);
        return authenticationProvider;
    }

    /**
     * <p> The following paths are unconditionally inspected by SecurityFilter
     * <p> Refer : {@link org.springframework.security.web.access.intercept.FilterSecurityInterceptor} </p>
     * @param httpSecurity
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .authorizeHttpRequests(auth -> auth
                        .mvcMatchers("/", "/users", "user/login/**").permitAll()
                        .mvcMatchers("/mypage").hasRole("USER")
                        .mvcMatchers("/messages").hasRole("MANAGER")
                        .mvcMatchers("/config").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .formLogin()
                .and()
                .build();
    }

    /**
     * <p> The paths below are filtered before the SecurityFilter. So paths below do not go through the SecurityFilter
     * <p> Refer : {@link org.springframework.security.web.access.intercept.FilterSecurityInterceptor} </p>
     * <p> Exclude In Spring Security Control. (Contains Static Resources)
     * <p> Ex) css, images, js , etc..
     * @return  {@link WebSecurity}.
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web
                .ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }


    //    @Bean
//    public InMemoryUserDetailsManager inMemoryUserDetailsManager(){
//        String password = passwordEncoder().encode("1111");
//        return new InMemoryUserDetailsManager(
//                User.withUsername("user").password(password).roles("USER").build(),
//                User.withUsername("manager").password(password).roles("USER", "MANAGER").build(),
//                User.withUsername("admin").password(password).roles("USER", "MANAGER", "ADMIN").build()
//        );
//    }
}
