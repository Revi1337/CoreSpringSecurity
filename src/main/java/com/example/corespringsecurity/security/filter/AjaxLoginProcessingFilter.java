package com.example.corespringsecurity.security.filter;

import com.example.corespringsecurity.domain.dto.AccountDto;
import com.example.corespringsecurity.security.token.AjaxAuthenticationToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private ObjectMapper objectMapper = new ObjectMapper();

    public AjaxLoginProcessingFilter(){
        super(new AntPathRequestMatcher("/api/login")); // 요청정보의 경로가 /api/login 와 매칭되는지 확인
    }

    public boolean isAjax(HttpServletRequest httpServletRequest) {
        return "XMLHttpRequest".equals(httpServletRequest.getHeader("X-Requested-With")); // 사용자의 요청이 Ajax 인지 판별. 그 기준은 Client 가 보내는 Ajax 요청 헤더값() 과의 일치여부로 판단할 것임.
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        if (!isAjax(request))
            throw new IllegalStateException("Authentication is not supported");
        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);
        if (!StringUtils.hasLength(accountDto.getUsername()) || !StringUtils.hasLength(accountDto.getPassword()))
            throw new IllegalArgumentException("Username or Password is Empty.");
        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());
        return this.getAuthenticationManager().authenticate(ajaxAuthenticationToken);
    }

}