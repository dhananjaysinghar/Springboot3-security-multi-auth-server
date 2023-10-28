# SPRING SECURITY OAUTH RESOURCE SERVER IMPLEMENTATION WITH MULTI AUTHORIZATION SERVER.

### Add below properties to `application.yml`
~~~
spring:
  security:
#    enabled: true # Default
#    ignore-uri: /actuator/health/** # Default
    swagger-enabled: true # Default is false
    oauth2:
      resource-server:
        azure:
          issuer-uri: ${AZURE_ISS}
          jwk-set-uri: ${AZURE_KEYSTORE}
        forgerock:
          issuer-uri: ${FORGEROCK_ISS}
          jwk-set-uri: ${FORGEROCK_KEYSTORE}
~~~

### Add below profile while running Component Test to skip jwt token expire check.
~~~
spring.profiles.active=componentTest
~~~

### To return custom error object configure below bean in your application.
~~~
  @Bean
  public SecurityErrorMapper errorMapper() {
    return (request, response, ex) ->
            Map.of("errorCode", "1", "errorMessage", ex.getMessage());
  }
~~~

### To resolve AccessRight with configured value use below bean.
~~~
app:
  endpoints:
    test:
      role: APIScope


    @PreAuthorize("hasAnyAuthority(@PlaceHolderResolver.resolve('${app.endpoints.test.role}'))")
    @GetMapping
    public Principal getMessage(Principal principal) {
        return principal;
    }
~~~