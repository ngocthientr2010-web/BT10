package vn.iotstar.services;

import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import vn.iotstar.exceptions.ExpiredJwtTokenException;
import vn.iotstar.exceptions.InvalidJwtException;

@Service
public class JwtService {
    private static final JWSAlgorithm ALGORITHM = JWSAlgorithm.HS256;

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    @Value("${security.jwt.issuer:jwt-springboot3}")
    private String issuer;

    @Value("${security.jwt.key-id:key-1}")
    private String keyId;

    public String extractUsername(String token) {
        return extractClaim(token, JWTClaimsSet::getSubject);
    }

    public <T> T extractClaim(String token, Function<JWTClaimsSet, T> claimsResolver) {
        return claimsResolver.apply(extractAllClaims(token));
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(Map.of(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public long getExpirationTime() {
        return jwtExpiration;
    }

    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        long now = System.currentTimeMillis();

        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder().subject(userDetails.getUsername())
                .issuer(issuer).issueTime(new Date(now)).expirationTime(new Date(now + expiration))
                .jwtID(UUID.randomUUID().toString());
        extraClaims.forEach(claimsBuilder::claim);

        JWSHeader header = new JWSHeader.Builder(ALGORITHM).type(JOSEObjectType.JWT).keyID(keyId).build();

        SignedJWT signedJWT = new SignedJWT(header, claimsBuilder.build());
        try {
            signedJWT.sign(new MACSigner(getSecretBytes()));
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot sign JWT", e);
        }
        return signedJWT.serialize();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username != null && username.equals(userDetails.getUsername());
    }

    private JWTClaimsSet extractAllClaims(String token) {
        final SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(token);
        } catch (ParseException e) {
            throw new InvalidJwtException("Malformed JWT", e);
        }

        if (!ALGORITHM.equals(signedJWT.getHeader().getAlgorithm())) {
            throw new InvalidJwtException("Unsupported JWT algorithm: " + signedJWT.getHeader().getAlgorithm());
        }

        try {
            if (!signedJWT.verify(new MACVerifier(getSecretBytes()))) {
                throw new InvalidJwtException("JWT signature does not match");
            }
        } catch (JOSEException e) {
            throw new InvalidJwtException("Cannot verify JWT signature", e);
        }

        final JWTClaimsSet claims;
        try {
            claims = signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new InvalidJwtException("Malformed JWT claims", e);
        }

        if (!issuer.equals(claims.getIssuer())) {
            throw new InvalidJwtException("Invalid JWT issuer");
        }

        Date exp = claims.getExpirationTime();
        if (exp == null) {
            throw new InvalidJwtException("JWT has no expiration time");
        }
        if (exp.before(new Date())) {
            throw new ExpiredJwtTokenException("JWT expired at " + exp);
        }
        return claims;
    }

    private byte[] getSecretBytes() {
        return Base64.getDecoder().decode(secretKey);
    }
}