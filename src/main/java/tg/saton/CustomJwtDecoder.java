package tg.saton;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.client.RestTemplate;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

public class CustomJwtDecoder implements JwtDecoder {

    @Value("${utils.central-base-url}")
    private String centralBaseUrl;

    private final RestTemplate restTemplate;

    public CustomJwtDecoder(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        try {
            // 1. Extraire les claims du JWT sans validation (juste parsing de la payload)
            Map<String, Object> claims = extractClaimsWithoutValidation(token);

            // 2. Récupérer le "server-id" (ou autre claim spécifique)
            String serverId = (String) claims.get("server-id");
            if (serverId == null) {
                throw new JwtException("Le claim 'server-id' est manquant dans le JWT");
            }

            // 3. Faire une requête à l'api central pour obtenir l'URL du JWKS
            String jwksUrl = getJwksUrl(serverId);

            // 4. Construire un décodeur JWT basé sur cette URL
            NimbusJwtDecoder jwtDecoder = createJwtDecoderFromJwksUrl(jwksUrl);

            // 5. Valider et décoder le JWT
            return jwtDecoder.decode(token);
        } catch (Exception e) {
            throw new JwtException("Erreur lors du décodage du JWT", e);
        }
    }

    private Map<String, Object> extractClaimsWithoutValidation(String token) {
        // Parse uniquement la partie "claims" du JWT (partie payload après le 1er point ".")
        String claimsPart = token.split("\\.")[1];
        String decodedClaims = new String(java.util.Base64.getUrlDecoder().decode(claimsPart));
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().readValue(decodedClaims, Map.class);
        } catch (Exception e) {
            throw new JwtException("Erreur lors de l'extraction des claims du JWT", e);
        }
    }

    private String getJwksUrl(String serverId) {
        // Faire une requête GET à l'API pour récupérer l'URL du JWKS
        String certsEndpoint =  centralBaseUrl + "/jwks/url?server_id=" + serverId;
        String response = restTemplate.getForObject(certsEndpoint, String.class);

        if (response == null || response.isEmpty()) {
            throw new JwtException("Impossible de récupérer l'URL JWKS depuis " + certsEndpoint);
        }

        return response + "/jwks"; // La réponse est supposée être une URL valide.
    }

    private NimbusJwtDecoder createJwtDecoderFromJwksUrl(String jwksUrl) throws MalformedURLException {
        // Construire un JWKSource basé sur l'URL JWKS
        JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(new URL(jwksUrl));

        // Utiliser NimbusJwtDecoder pour valider le JWT avec les JWKS
        return NimbusJwtDecoder.withJwkSetUri(jwksUrl).build();
    }
}
