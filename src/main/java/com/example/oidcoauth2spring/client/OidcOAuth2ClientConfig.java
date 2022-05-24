package com.example.oidcoauth2spring.client;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

@Configuration
public class OidcOAuth2ClientConfig {

    @Value("${google.client-id}")
    String googleClientId;

    @Value("${google.client-secret}")
    String googleClientSecret;

    @Value("${github.client-id}")
    String githubClientId;

    @Value("${github.client-secret}")
    String githubClientSecret;

    @Bean
    ClientRegistrationRepository googleClientRegistration() {
        return new InMemoryClientRegistrationRepository(googleOidcOauthClient(), googleOauthClient(),
            githubOidcOauthClient(), githubOauthClient());
    }

    @Bean
    public OAuth2AuthorizedClientService auth2AuthorizedClientService(ClientRegistrationRepository clientRegistrationRepository) {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
    }

    @Bean
    public AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientServiceAndManager(
        ClientRegistrationRepository clientRegistrationRepository,
        OAuth2AuthorizedClientService authorizedClientService) {

        OAuth2AuthorizedClientProvider authorizedClientProvider =
            OAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials()
                .build();

        AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager =
            new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                clientRegistrationRepository, authorizedClientService);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        return authorizedClientManager;
    }

    private ClientRegistration googleOidcOauthClient() {
        return ClientRegistration
            .withRegistrationId("google_oidc_oauth")
            .clientId(googleClientId)
            .clientSecret(googleClientSecret)
            .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
            .userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
            .scope("openid", "profile", "email")
            .redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
            .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
            .tokenUri("https://www.googleapis.com/oauth2/v4/token")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .providerConfigurationMetadata(Map.of("jwkSetUri", "https://www.googleapis.com/oauth2/v3/certs"))
            .build();
    }

    private ClientRegistration googleOauthClient() {
        return ClientRegistration
            .withRegistrationId("google_oauth")
            .userNameAttributeName("sub")
            .clientId(googleClientId)
            .clientSecret(googleClientSecret)
            .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
            .userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
            .scope("profile", "email")
            .redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
            .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
            .tokenUri("https://www.googleapis.com/oauth2/v4/token")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .build();
    }

    private ClientRegistration githubOauthClient() {
        return ClientRegistration
            .withRegistrationId("github_oauth")
            .userNameAttributeName("id")
            .clientId(githubClientId)
            .clientSecret(githubClientSecret)
            .userInfoUri("https://api.github.com/user")
            .userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
            .scope("profile", "email")
            .redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
            .authorizationUri("https://github.com/login/oauth/authorize")
            .tokenUri("https://github.com/login/oauth/access_token")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .build();
    }

    private ClientRegistration githubOidcOauthClient() {
        return ClientRegistration
            .withRegistrationId("github_oidc_oauth")
            .userNameAttributeName("id")
            .clientId(githubClientId)
            .clientSecret(githubClientSecret)
            .userInfoUri("https://api.github.com/user")
            .userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
            .scope("openid", "profile", "email")
            .redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
            .authorizationUri("https://github.com/login/oauth/authorize")
            .tokenUri("https://github.com/login/oauth/access_token")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .build();
    }
}
