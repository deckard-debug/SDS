package com.example.demo.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "ip_blacklist")
@Data
@NoArgsConstructor
public class IpBlacklist {
    
    @Id
    private String ip;
    private String reason;
    private LocalDateTime expiresAt;
    private LocalDateTime createdAt;
}