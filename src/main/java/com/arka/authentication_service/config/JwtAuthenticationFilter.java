package com.arka.authentication_service.config;

import com.arka.authentication_service.service.JWTService;
import com.arka.authentication_service.service.SecurityUser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Configuration
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JWTService jwtService;
    private final SecurityUser securityUser;


    public JwtAuthenticationFilter(JWTService jwtService, SecurityUser securityUser) {
        this.jwtService = jwtService;
        this.securityUser = securityUser;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    )
            throws ServletException, IOException {

            final String authHeader = request.getHeader("Authorization");
            final String jwt;
            final String userEmail;

        if (authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }

        jwt=authHeader.substring(7);

        try {
            userEmail = jwtService.extractUsername(jwt);
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){

                UserDetails userDetails = this.securityUser.loadUserByUsername(userEmail);

                if (jwtService.isTokenValid(jwt,userDetails.getUsername())){

                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    authToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );

                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }

        } catch (Exception e) {
            logger.error("can´t set user authentication:{}"+e.getMessage());
        }
        filterChain.doFilter(request,response);
    }

}
