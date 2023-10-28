package com.security.test.utils;

import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;


@Slf4j
@RequiredArgsConstructor
public class AccessControlUtils {

    private final Environment environment;

    public String[] resolve(String... values) {
        HttpServletRequest request = ((ServletRequestAttributes) Objects.requireNonNull(RequestContextHolder.getRequestAttributes())).getRequest();
        var valueArray = Stream.of(values).map(this::resolvePlaceHolderValues).flatMap(Collection::stream).toList().toArray(String[]::new);
        log.info("Configured access control lists to be verified for this endpoint - {}:{} ; {}", request.getMethod(), request.getRequestURI(), Arrays.toString(valueArray));
        return valueArray;
    }

    private List<String> resolvePlaceHolderValues(String value) {
        String placeHolderValue = Constants.REGEX_PLACEHOLDER.matcher(value).find() ? this.environment.getProperty(value.replaceAll(Constants.REGEX_PLACEHOLDER.pattern(), Constants.EMPTY_STRING)) : value;
        if (Objects.isNull(placeHolderValue)) {
            return Collections.emptyList();
        }
        List<String> configuredAccessRights = new ArrayList<>();
        if (placeHolderValue.contains(Constants.SEPARATOR)) {
            placeHolderValue = placeHolderValue.replaceAll(Constants.EMPTY_SPACE_STRING, Constants.EMPTY_STRING);
            configuredAccessRights.addAll(Arrays.asList(placeHolderValue.split(Constants.SEPARATOR)));
        } else {
            configuredAccessRights.add(placeHolderValue.trim());
        }
        return configuredAccessRights;
    }
}
