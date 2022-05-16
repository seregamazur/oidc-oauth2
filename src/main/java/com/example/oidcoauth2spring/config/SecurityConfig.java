package com.example.oidcoauth2spring.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http
            .authorizeRequests(a -> a
                .antMatchers("/", "/oauth/**").permitAll()
                .anyRequest().authenticated())
            .csrf(c -> c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
            .logout(l -> l.logoutSuccessUrl("/").permitAll())
            .oauth2Login(o -> o
                .successHandler((request, response, authentication) -> response.sendRedirect("/")));
    }
}
