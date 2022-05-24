package com.example.oidcoauth2spring.resource;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OIdcOAuth2Controller {

    @GetMapping("/oidc-user")
    public Map<String, ?> user(@AuthenticationPrincipal OidcUser principal) {
        Map<String, Object> userInfo = new LinkedHashMap<>();
        userInfo.put("token", principal.getIdToken().getTokenValue());
        return userInfo;
    }
}
