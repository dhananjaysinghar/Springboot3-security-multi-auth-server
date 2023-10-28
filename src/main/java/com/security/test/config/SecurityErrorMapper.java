package com.security.test.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@FunctionalInterface
public interface SecurityErrorMapper {
    Object map(
            HttpServletRequest request, HttpServletResponse response, RuntimeException ex);
}
