package com.security.test.controller;

import java.security.Principal;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {

    @PreAuthorize("hasAnyAuthority(@PlaceHolderResolver.resolve('${app.endpoints.test.role}'))")
    @GetMapping
    public Object getMessage(Principal principal) {
        return principal;
    }
}
