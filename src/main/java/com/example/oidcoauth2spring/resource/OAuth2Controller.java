package com.example.oidcoauth2spring.resource;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OAuth2Controller {

    @GetMapping("/user")
    public Map<String, ?> user(@AuthenticationPrincipal OAuth2User principal) {
        Map<String, Object> userInfo = new LinkedHashMap<>();
        userInfo.put("name", principal.getAttribute("name"));
        userInfo.put("picture", principal.getAttribute("picture"));
        userInfo.put("scope", principal.getAuthorities().stream()
            .filter(p -> p.getAuthority().startsWith("SCOPE_"))
            .map(Object::toString)
            .collect(Collectors.joining(", ")));
        return userInfo;
    }
}
