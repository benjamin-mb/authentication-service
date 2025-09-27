package com.arka.authentication_service.service;

import com.arka.authentication_service.model.Usuario;
import com.arka.authentication_service.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

@Service
public class SecurityUser implements UserDetailsService {

    private final UserRepository repository;

    public SecurityUser(UserRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Usuario usuario =repository.findByEmail(email.trim())
                .orElseThrow(()-> new UsernameNotFoundException("user "+email+" was not found"));
        String rol= "ROLE_"+usuario.getTipo().toString().toUpperCase();
        return new org.springframework.security.core.userdetails.User(
                usuario.getEmail(),
                usuario.getPassword(),
                Collections.singletonList(new SimpleGrantedAuthority(rol)));

    }
}
