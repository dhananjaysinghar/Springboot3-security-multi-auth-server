package com.security.test.config;

import com.google.common.cache.CacheBuilder;
import com.nimbusds.jwt.JWTParser;
import com.security.test.utils.Constants;
import com.security.test.utils.AccessControlUtils;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

@Configuration
@EnableWebSecurity
@Slf4j
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {
    @Value("${spring.security.jwks.retrieve.ttl:300}")
    private Long jwkSetTtl;
    @Value("${spring.security.ignore-uri:}")
    private String[] configuredIgnoreUri;
    @Value("${spring.security.swagger-enabled:false}")
    private boolean isSwaggerEnabled;

    private final ApplicationContext applicationContext;

    /**
     * SecurityFilterChain configuration for application when security is enabled.
     *
     * @param http http.
     * @return SecurityFilterChain.
     * @throws Exception ex.
     */
    @Bean
    @ConditionalOnProperty(value = "spring.security.enabled", havingValue = "true", matchIfMissing = true)
    public SecurityFilterChain securityFilterChain(HttpSecurity http, SecurityErrorMapper securityErrorMapper) throws Exception {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new GrantedAuthoritiesExtractor());
        http.csrf(AbstractHttpConfigurer::disable).cors(AbstractHttpConfigurer::disable)
                .sessionManagement(e -> e.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(getIgnoredUri()).permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 ->
                        oauth2.jwt(jwt ->
                                        jwt.jwtAuthenticationConverter(jwtAuthenticationConverter))
                                .authenticationEntryPoint(new AuthenticationExceptionHandler(securityErrorMapper)))
                .exceptionHandling(ex -> ex.accessDeniedHandler(new AuthorizationExceptionHandler(securityErrorMapper)));
        return http.build();
    }

    /**
     * SecurityFilterChain configuration for application when security is disabled.
     *
     * @param http http.
     * @return SecurityFilterChain.
     * @throws Exception ex.
     */
    @Bean
    @ConditionalOnProperty(value = "spring.security.enabled", havingValue = "false")
    public SecurityFilterChain filterChainWithoutSecurity(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(e -> e.anyRequest().permitAll());
        return http.build();
    }


    /**
     * JWT decoder for token decode and validation.
     *
     * @return JwtDecoder.
     */
    @Bean
    @Primary
    public JwtDecoder jwtDecoder() {
        return token -> {
            String iss;
            try {
                Map<String, Object> claims = JWTParser.parse(token).getJWTClaimsSet().getClaims();
                iss = String.valueOf(claims.getOrDefault("iss", Constants.EMPTY_STRING));
            } catch (Exception ex) {
                log.error(ex.getMessage());
                throw new InvalidBearerTokenException(ex.getMessage());
            }
            return iss.contains(Constants.FORGE_ROCK_ISS_CONTENT)
                    ? getNimbusReactiveJwtDecoder(
                    Constants.FORGE_ROCK_JWT_DECODER_BEAN_NAME,
                    "Forgerock Oauth2 server details not configured in service")
                    .decode(token)
                    : getNimbusReactiveJwtDecoder(
                    Constants.AZURE_AD_JWT_DECODER_BEAN_NAME,
                    "Azure AD Oauth2 server details not not configured in service")
                    .decode(token);
        };
    }

    /**
     * Azure AD decoder for non test profile.
     *
     * @param environment Environment
     * @return NimbusReactiveJwtDecoder
     */
    @Bean(Constants.AZURE_AD_JWT_DECODER_BEAN_NAME)
    @ConditionalOnExpression(Constants.AZURE_AD_JWT_DECODER_BEAN_CONDITION)
    @Profile({"!componentTest"})
    public NimbusJwtDecoder azureADJwtDecoder(Environment environment) {
        return getJwtDecoder(
                environment.getProperty(Constants.AZURE_AD_KEY_STORE),
                environment.getProperty(Constants.AZURE_AD_ISS), jwkSetTtl, true);
    }

    /**
     * Azure AD decoder for componentTest profile.
     *
     * @param environment Environment
     * @return NimbusReactiveJwtDecoder
     */
    @Bean(Constants.AZURE_AD_JWT_DECODER_BEAN_NAME)
    @ConditionalOnExpression(Constants.AZURE_AD_JWT_DECODER_BEAN_CONDITION)
    @Profile({"componentTest"})
    public NimbusJwtDecoder azureADJwtDecoderWithExpiredTokenTest(Environment environment) {
        return getJwtDecoder(
                environment.getProperty(Constants.AZURE_AD_KEY_STORE),
                environment.getProperty(Constants.AZURE_AD_ISS), jwkSetTtl, false);
    }

    /**
     * Forgerock decoder for non test profile.
     *
     * @param environment Environment
     * @return NimbusReactiveJwtDecoder
     */
    @Bean(Constants.FORGE_ROCK_JWT_DECODER_BEAN_NAME)
    @ConditionalOnExpression(Constants.FORGE_ROCK_JWT_DECODER_BEAN_CONDITION)
    @Profile({"!componentTest"})
    public NimbusJwtDecoder forgeRockJwtDecoder(Environment environment) {
        return getJwtDecoder(
                environment.getProperty(Constants.FORGE_ROCK_KEY_STORE),
                environment.getProperty(Constants.FORGE_ROCK_ISS), jwkSetTtl, true);
    }

    /**
     * Forgerock decoder for componentTest profile.
     *
     * @param environment Environment
     * @return NimbusReactiveJwtDecoder
     */
    @Bean(Constants.FORGE_ROCK_JWT_DECODER_BEAN_NAME)
    @ConditionalOnExpression(Constants.FORGE_ROCK_JWT_DECODER_BEAN_CONDITION)
    @Profile({"componentTest"})
    public NimbusJwtDecoder forgeRockJwtDecoderWithExpiredTokenTest(Environment environment) {
        return getJwtDecoder(
                environment.getProperty(Constants.FORGE_ROCK_KEY_STORE),
                environment.getProperty(Constants.FORGE_ROCK_ISS), jwkSetTtl, false);
    }

    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    public SecurityErrorMapper defaultSecurityErrorMapper() {
        return new DefaultSecurityErrorMapper();
    }

    @Bean("PlaceHolderResolver")
    public AccessControlUtils placeHolderResolver(Environment environment) {
        return new AccessControlUtils(environment);
    }

    /**
     * Implementation class of Converter to extract roles.
     */

    public static class GrantedAuthoritiesExtractor implements Converter<Jwt, Collection<GrantedAuthority>> {
        public Collection<GrantedAuthority> convert(Jwt jwt) {
            Collection<?> authorities = (Collection<?>) jwt.getClaims()
                    .getOrDefault("roles", Collections.emptyList());
            Collection<GrantedAuthority> authorityCollection;
            if (authorities.isEmpty()) {
                authorities = (Collection<?>) jwt.getClaims()
                        .getOrDefault("scope", Collections.emptyList());

                if (authorities.isEmpty() && jwt.getClaims()
                        .get("scp") != null) {
                    authorities = Stream.of(String.valueOf(jwt.getClaims()
                            .get("scp")).split(" ")).collect(Collectors.toList());
                }
                authorityCollection = authorities.stream().map(Object::toString)
                        .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
            } else {
                authorityCollection = authorities.stream().map(Object::toString)
                        .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
            }

            String defaultScope = "APIScope";
            if (!String.valueOf(jwt.getClaims().get("iss")).contains(Constants.FORGE_ROCK_ISS_CONTENT) && authorityCollection.stream().noneMatch(e -> e.getAuthority().contains(defaultScope))) {
                authorityCollection.add(new SimpleGrantedAuthority(defaultScope));
            }
            log.debug("Validated token successfully with claims: {}", jwt.getClaims());
            return authorityCollection;
        }
    }

    private String[] getIgnoredUri() {
        String[] ignoredUriList = Constants.SECURITY_IGNORE_URI;
        if (!Objects.isNull(configuredIgnoreUri) && configuredIgnoreUri.length > 0) {
            ignoredUriList = Stream.of(configuredIgnoreUri, Constants.SECURITY_IGNORE_URI).flatMap(Stream::of).toArray(String[]::new);
        }

        if (isSwaggerEnabled) {
            ignoredUriList = Stream.of(ignoredUriList, Constants.SWAGGER_IGNORE_URI)
                    .flatMap(Stream::of).toArray(String[]::new);
        }
        return ignoredUriList;
    }

    private NimbusJwtDecoder getJwtDecoder(String jwks, String iss, Long jwkSetTtl, boolean isExpireCheckRequired) {
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setInterceptors(Collections.singletonList((request, body, execution) -> {
            Instant startTime = Instant.now();
            log.info("Calling jwks uri : {}", request.getURI());
            var res =  execution.execute(request, body);
            Instant endTime = Instant.now();
            log.info("Received response from jwks uri status : {}, time taken: {} ms", res.getStatusCode(),
                    Duration.between(startTime, endTime).toMillis());
            return res;
        }));
        Cache jwkSetCache = new ConcurrentMapCache(Constants.JWK_SET_CACHE, CacheBuilder.newBuilder()
                .expireAfterWrite(jwkSetTtl, TimeUnit.MINUTES).build().asMap(), false);

        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwks)
                .restOperations(restTemplate)
                .cache(jwkSetCache).build();

        OAuth2TokenValidator<Jwt> validator = isExpireCheckRequired
                ? JwtValidators.createDefaultWithIssuer(iss)
                : new DelegatingOAuth2TokenValidator<>(List.of(new JwtIssuerValidator(iss)));

        jwtDecoder.setJwtValidator(validator);
        return jwtDecoder;
    }

    private NimbusJwtDecoder getNimbusReactiveJwtDecoder(
            String beanName, String exMessage) {
        try {
            return applicationContext.getBean(beanName, NimbusJwtDecoder.class);
        } catch (Exception ex) {
            log.error(ex.getMessage());
            throw new ProviderNotFoundException(exMessage);
        }
    }
}
