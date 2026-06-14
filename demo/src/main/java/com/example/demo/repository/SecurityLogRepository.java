package com.example.demo.repository;

import com.example.demo.model.SecurityLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SecurityLogRepository extends JpaRepository<SecurityLog, Long> {
    // JpaRepository ya proporciona save(), findAll(), findById(), delete()
}