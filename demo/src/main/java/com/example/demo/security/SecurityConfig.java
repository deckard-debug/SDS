package com.example.demo.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.demo.repository.UserRepository;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {
    
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    
    @Bean
    public IpFilter ipFilter() {
        return new IpFilter();
    }
    
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtTokenProvider, userDetailsService());
    }
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.info("Configurando SecurityFilterChain...");
        
        http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> {
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                log.info("Sesiones configuradas como STATELESS");
            })
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/",
                    "/index.html",
                    "/login.html",
                    "/register.html",
                    "/recover.html",
                    "/dashboard.html",
                    "/css/**",
                    "/js/**",
                    "/static/**",
                    "/api/auth/**",
                    "/api/public/**",
                    "/error"

                ).permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(ipFilter(), UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        
        log.info("SecurityFilterChain configurado correctamente");
        return http.build();
    }
    
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            log.info("Buscando usuario: {}", username);
            return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + username));
        };
    }
}