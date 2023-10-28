package com.security.test.config;

import com.security.test.utils.SecurityUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

@Slf4j
@RequiredArgsConstructor
public class AuthorizationExceptionHandler implements AccessDeniedHandler {

    private final SecurityErrorMapper securityErrorMapper;

    @Override
    public void handle(HttpServletRequest httpServletRequest,
                       HttpServletResponse httpServletResponse, AccessDeniedException ex) {
        log.error("Authorization Error Occurred: {}", ex.getMessage());
        httpServletResponse.setStatus(HttpStatus.FORBIDDEN.value());
        httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
        var errorObject = securityErrorMapper.map(httpServletRequest, httpServletResponse, ex);
        SecurityUtils.printOutputStream(httpServletResponse, errorObject);
    }
}
