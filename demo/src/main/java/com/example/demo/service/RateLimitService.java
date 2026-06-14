package com.example.demo.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
public class RateLimitService {

    // Estructura: Map<IP:Acción, Intentos>
    private final Map<String, Integer> attempts = new ConcurrentHashMap<>();
    private final Map<String, Long> resetTime = new ConcurrentHashMap<>();

    /**
     * Verifica si una IP puede realizar una acción
     * @param ip Dirección IP
     * @param action Tipo de acción (login, register, etc.)
     * @param maxAttempts Máximo de intentos permitidos
     * @param windowSeconds Ventana de tiempo en segundos
     * @return true si está dentro del límite, false si excedió
     */
    public boolean checkRateLimit(String ip, String action, int maxAttempts, int windowSeconds) {
        String key = ip + ":" + action;
        long now = System.currentTimeMillis();
        
        // Limpiar entradas antiguas periódicamente
        cleanOldEntries();
        
        if (resetTime.containsKey(key) && resetTime.get(key) > now) {
            int count = attempts.getOrDefault(key, 0);
            if (count >= maxAttempts) {
                log.warn("Rate limit exceeded for {}: {} attempts in {}s", key, count, windowSeconds);
                return false;
            }
            attempts.put(key, count + 1);
        } else {
            attempts.put(key, 1);
            resetTime.put(key, now + (windowSeconds * 1000L));
        }
        
        return true;
    }

    /**
     * Obtiene el número de intentos restantes
     */
    public int getRemainingAttempts(String ip, String action, int maxAttempts) {
        String key = ip + ":" + action;
        long now = System.currentTimeMillis();
        
        if (resetTime.containsKey(key) && resetTime.get(key) > now) {
            int count = attempts.getOrDefault(key, 0);
            return Math.max(0, maxAttempts - count);
        }
        return maxAttempts;
    }

    /**
     * Resetea el límite para una IP/acción específica
     */
    public void resetLimit(String ip, String action) {
        String key = ip + ":" + action;
        attempts.remove(key);
        resetTime.remove(key);
        log.debug("Rate limit reset for {}", key);
    }
    
    /**
     * Limpia entradas antiguas para evitar memoria infinita
     */
    private void cleanOldEntries() {
        long now = System.currentTimeMillis();
        resetTime.entrySet().removeIf(entry -> entry.getValue() < now);
        attempts.keySet().removeIf(key -> !resetTime.containsKey(key));
    }
    
    // Método para compatibilidad con AuthService
    public int getAttempts(String ip, String action) {
        String key = ip + ":" + action;
        return attempts.getOrDefault(key, 0);
    }
}