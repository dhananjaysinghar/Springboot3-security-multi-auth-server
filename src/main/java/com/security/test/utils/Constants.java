package com.security.test.utils;

import java.util.regex.Pattern;

public class Constants {

    public static final String FORGE_ROCK_KEY_STORE = "spring.security.oauth2.resource-server.forgerock.jwk-set-uri";
    public static final String FORGE_ROCK_ISS = "spring.security.oauth2.resource-server.forgerock.issuer-uri";
    public static final String AZURE_AD_KEY_STORE = "spring.security.oauth2.resource-server.azure.jwk-set-uri";
    public static final String AZURE_AD_ISS = "spring.security.oauth2.resource-server.azure.issuer-uri";
    public static final String AZURE_AD_ISS_CONTENT = "microsoftonline.com";
    public static final String FORGE_ROCK_ISS_CONTENT = "forgerock.com";
    public static final String AZURE_AD_JWT_DECODER_BEAN_NAME = "AZURE_AD_JWT_DECODER";
    public static final String FORGE_ROCK_JWT_DECODER_BEAN_NAME = "FORGE_ROCK_JWT_DECODER";
    public static final String AZURE_AD_JWT_DECODER_BEAN_CONDITION = "!T(org.springframework.util.StringUtils).isEmpty('${spring.security.oauth2.resource-server.azure.jwk-set-uri:}')";
    public static final String FORGE_ROCK_JWT_DECODER_BEAN_CONDITION = "!T(org.springframework.util.StringUtils).isEmpty('${spring.security.oauth2.resource-server.forgerock.jwk-set-uri:}')";
    public static final String JWK_SET_CACHE = "jwkSetCache";
    public static final String EMPTY_STRING = "";
    public static final String[] SECURITY_IGNORE_URI = new String[]{"/actuator/health/**", "/actuator/prometheus", "/actuator/metrics"};

    public static final String[] SWAGGER_IGNORE_URI = new String[]{"/v3/api-docs/**", "/v3/**", "/swagger-ui/**"};
    public static final String TIME_STAMP_FORMAT = "yyyy-MM-dd'T'HH:mm:ss";
    public static final Pattern REGEX_PLACEHOLDER = Pattern.compile("[${}]");
    public static final String SEPARATOR = ",";
    public static final String EMPTY_SPACE_STRING = " ";

}
