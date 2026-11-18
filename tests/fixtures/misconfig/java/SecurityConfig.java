package com.example;

import io.jsonwebtoken.Jwts;
import java.util.Random;
import org.springframework.web.bind.annotation.CrossOrigin;

public class SecurityConfig {
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        // VULNERABLE: CSRF disabled.
        http.csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }

    CorsConfiguration cors() {
        CorsConfiguration c = new CorsConfiguration();
        c.setAllowedOriginPatterns(List.of("*")); // VULNERABLE with credentials below
        c.setAllowCredentials(true);
        return c;
    }

    Claims parse(String token) {
        return Jwts.parser().build().parseClaimsJwt(token).getBody(); // VULNERABLE (unsigned)
    }

    Cookie sessionCookie(String value) {
        Cookie cookie = new Cookie("SESSION", value);
        cookie.setHttpOnly(false); // VULNERABLE
        return cookie;
    }

    String resetToken() {
        return Long.toString(new Random().nextLong()); // VULNERABLE (reset token)
    }
}

@CrossOrigin(origins = "https://app.example") // SAFE
class OrdersApi {}
