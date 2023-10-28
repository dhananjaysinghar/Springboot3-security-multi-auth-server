package com.security.test.config;

import com.security.test.utils.SecurityUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;

public class DefaultSecurityErrorMapper implements SecurityErrorMapper {
    @Override
    public Object map(HttpServletRequest request, HttpServletResponse response, RuntimeException ex) {
        return SecurityUtils.getErrorObject(request, ex.getMessage(), HttpStatus.valueOf(response.getStatus()));
    }
}
