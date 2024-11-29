package tg.saton;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final RestTemplate restTemplate;
    private final JwtAuthConverter jwtAuthConverter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/public").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(
                                jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter)
                        ) // Utilise le décoder personnalisé
                );

        return http.build();
    }

    @Bean
    public JwtDecoder customJwtDecoder() {
        // Retourne une instance de ton décodeur personnalisé
        return new CustomJwtDecoder(restTemplate);
    }
}

