package com.example.demo.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@Slf4j
public class IpFilter extends OncePerRequestFilter {
    
    @Value("${app.security.allowed-ips:127.0.0.1,0:0:0:0:0:0:0:1}")
    private List<String> allowedIps;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        
        String path = request.getRequestURI();
        if (path.startsWith("/api/auth/")) {
            filterChain.doFilter(request, response);
            return;
        }
        
        String clientIp = getClientIp(request);
        log.debug("Verificando IP: {}", clientIp);
        
        if (!isIpAllowed(clientIp)) {
            log.warn("IP bloqueada: {}", clientIp);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Acceso no autorizado desde tu IP: " + clientIp + "\"}");
            return;
        }
        
        filterChain.doFilter(request, response);
    }
    
    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
    
    private boolean isIpAllowed(String ip) {
        if (allowedIps == null || allowedIps.isEmpty()) {
            return true;
        }
        
        // Normalizar IPv6 localhost
        String normalizedIp = ip.equals("0:0:0:0:0:0:0:1") ? "127.0.0.1" : ip;
        
        for (String allowed : allowedIps) {
            if (allowed.equals(normalizedIp) || allowed.equals(ip)) {
                return true;
            }
            // Soporte para rangos CIDR (básico)
            if (allowed.contains("/")) {
                if (isIpInRange(normalizedIp, allowed)) {
                    return true;
                }
            }
        }
        return false;
    }
    
    private boolean isIpInRange(String ip, String cidr) {
        // Implementación básica para rangos /24
        if (cidr.endsWith("/24")) {
            String network = cidr.substring(0, cidr.length() - 3);
            return ip.startsWith(network);
        }
        return false;
    }
}