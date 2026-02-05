package com.example.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .cors().configurationSource(request -> {
                var cors = new CorsConfiguration();
                cors.allowedOrigins("*");
                cors.setAllowedMethods(List.of("*"));
                return cors;
            })
            .and()
            .authorizeRequests()
            .antMatchers("/public/**").permitAll()
            .antMatchers("/api/**").authenticated();
    }
}
