package com.ajdevscourses.app_security.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping(path="/accounts")
public class AccountsController {

    // @PreAuthorize("hasAnyAuthority('VIEW_ACCOUNT', 'VIEW_CARDS')")  // Se comenta al controlarlo por security
    @GetMapping
    public Map<String,String> accounts() {
        // .. business logic
        return Collections.singletonMap("msj", "accounts");
    }
}
