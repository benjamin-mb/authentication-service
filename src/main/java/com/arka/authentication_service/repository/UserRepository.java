package com.arka.authentication_service.repository;

import com.arka.authentication_service.model.Usuario;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
@Repository
public interface UserRepository extends JpaRepository<Usuario,Integer> {
    Optional<Usuario>findByEmail(String email);
}
