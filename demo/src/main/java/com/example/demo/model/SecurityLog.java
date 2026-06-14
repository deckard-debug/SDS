package com.example.demo.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;

import java.time.LocalDateTime;

@Entity
@Table(name = "security_logs")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityLog {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String ip;
    
    @Enumerated(EnumType.STRING)
    private EventType eventType;
    
    @Column(columnDefinition = "TEXT")
    private String details;
    
    private String username;
    
    @CreatedDate
    private LocalDateTime createdAt;
    
    public enum EventType {
        LOGIN_SUCCESS, LOGIN_FAILED, LOGOUT, PASSWORD_CHANGE,
        TWO_FACTOR_SENT, TWO_FACTOR_VERIFIED, ACCOUNT_LOCKED,
        IP_BLOCKED, RATE_LIMIT_EXCEEDED, BACKUP_CREATED,
        BACKUP_RESTORED, REGISTER_SUCCESS, REGISTER_FAILED
    }
}