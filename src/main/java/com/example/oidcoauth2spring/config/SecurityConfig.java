package com.example.oidcoauth2spring.config;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import lombok.SneakyThrows;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http
            .authorizeRequests(a -> a
                .antMatchers("/", "/oidc-index.html", "/oauth/**").permitAll()
                .anyRequest().authenticated())
            .csrf(c -> c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
            .logout(l -> l.logoutSuccessUrl("/").permitAll())
            .oauth2Login(o -> o.successHandler((request, response, authentication) -> {
                    if (Arrays.asList(request.getParameterMap().get("scope")).contains("openid")) {
                        response.sendRedirect("/oidc-index.html");
                    } else {
                        response.sendRedirect("/");
                    }
                }));
    }

    /**
     * Workaround for client registration jwkSetUri
     */
    @Bean
    public JwtDecoderFactory<ClientRegistration> jwtDecoderFactory() {

        final JwtDecoder decoder = new JwtDecoder() {

            @SneakyThrows
            @Override
            public Jwt decode(String token) throws JwtException {
                JWT jwt = JWTParser.parse(token);
                return createJwt(token, jwt);
            }

            private Jwt createJwt(String token, JWT parsedJwt) {
                try {
                    Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());
                    Map<String, Object> claims = new LinkedHashMap<>(parsedJwt.getJWTClaimsSet().getClaims());
                    claims.put("exp", ((Date) claims.get("exp")).toInstant());
                    claims.put("iat", ((Date) claims.get("iat")).toInstant());
                    return Jwt.withTokenValue(token)
                        .headers(h -> h.putAll(headers))
                        .claims(c -> c.putAll(claims))
                        .build();
                } catch (Exception ex) {
                    if (ex.getCause() instanceof ParseException) {
                        throw new JwtException("Malformed payload");
                    } else {
                        throw new JwtException(ex.getMessage(), ex);
                    }
                }
            }
        };
        return context -> decoder;
    }

}
