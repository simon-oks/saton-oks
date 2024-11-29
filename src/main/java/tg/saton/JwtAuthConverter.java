package tg.saton;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    @Value("${jwt.auth.converter.principle-attribute:sub}") // Valeur par défaut : "sub"
    private String principleAttribute;

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
        Collection<? extends GrantedAuthority> authorities = Stream.concat(
                jwtGrantedAuthoritiesConverter.convert(jwt)
                        .stream(),
                extractAllResourceRoles(jwt).stream() // Extraction des rôles dynamiques
        ).collect(Collectors.toSet());

        return new JwtAuthenticationToken(
                jwt,
                authorities,
                getPrincipleClaimName(jwt)
        );
    }

    private String getPrincipleClaimName(Jwt jwt) {
        return jwt.getClaim(principleAttribute != null ? principleAttribute : JwtClaimNames.SUB);
    }

    private Collection<? extends GrantedAuthority> extractAllResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess == null) {
            return Set.of(); // Aucun "resource_access" présent
        }

        return resourceAccess.values().stream()
                .filter(value -> value instanceof Map) // Vérifie que la valeur est une Map
                .map(value -> (Map<String, Object>) value) // Cast en Map
                .filter(resource -> resource.containsKey("roles")) // Vérifie la présence des rôles
                .flatMap(resource -> ((Collection<String>) resource.get("roles")).stream()) // Extraction des rôles
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role)) // Préfixe "ROLE_"
                .collect(Collectors.toSet());
    }
}
