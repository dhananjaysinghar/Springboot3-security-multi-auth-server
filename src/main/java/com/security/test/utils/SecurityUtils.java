package com.security.test.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.security.test.models.ExceptionResponse;
import com.security.test.models.GlobalExceptionResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.OutputStream;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class SecurityUtils {


    @SneakyThrows
    public static <T> void printOutputStream(HttpServletResponse response, T errorObject) {
        response.setStatus(response.getStatus());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        OutputStream out = response.getOutputStream();
        log.error("Error Details : {}", errorObject);
        objectMapper().writeValue(out, errorObject);
        out.flush();
    }

    @SneakyThrows
    public static void printOutputStream(HttpServletRequest request, HttpServletResponse response, String message, HttpStatus status) {
        GlobalExceptionResponse errorObject = getErrorObject(request, message, status);
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        OutputStream out = response.getOutputStream();
        log.error("Error Details : {}", errorObject);
        objectMapper().writeValue(out, errorObject);
        out.flush();
    }

    public static GlobalExceptionResponse getErrorObject(HttpServletRequest request, String message, HttpStatus status) {
        return GlobalExceptionResponse.builder().httpMethod(String.valueOf(request.getMethod()))
                .requestUri(String.valueOf(request.getRequestURI()))
                .statusCode(status.value()).statusText(status.toString())
                .errorTimestamp(currentTimeStamp())
                .exceptions(List.of(ExceptionResponse.builder()
                        .exceptionCode("1").exceptionMessage(message).build()))
                .build();
    }

    public static String currentTimeStamp() {
        return DateTimeFormatter.ofPattern(Constants.TIME_STAMP_FORMAT).format(LocalDateTime.now(ZoneOffset.UTC));
    }

    public static ObjectMapper objectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        return objectMapper;
    }
}
