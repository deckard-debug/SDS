package com.example.demo.repository;

import com.example.demo.model.IpBlacklist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface IpBlacklistRepository extends JpaRepository<IpBlacklist, String> {
    Optional<IpBlacklist> findByIpAndExpiresAtAfter(String ip, LocalDateTime now);
}