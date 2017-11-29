package com.example;

import io.jsonwebtoken.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import static com.example.SecurityConstants.HEADER_STRING;
import static com.example.SecurityConstants.TOKEN_PREFIX;


public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private static final Logger log = LoggerFactory.getLogger(JwtAuthorizationFilter.class);

    public JwtAuthorizationFilter(AuthenticationManager authManager) {
        super(authManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        String header = req.getHeader(HEADER_STRING);

        if (header == null || !header.startsWith(TOKEN_PREFIX)) {
            chain.doFilter(req, res);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(HEADER_STRING);
        if (token != null) {
            // parse the token.
            String user = null;
            try {
                user = Jwts.parser()
                        .setSigningKeyResolver(new OpenidSigningKeyResolver())
                        .parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
                        .getBody()
                        .getSubject();
            } catch (Exception e) {
                e.printStackTrace();
            }

            if (user != null) {
                log.info("Request token verification success. {}", user);
                return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
            }
            log.info("Request token verification failure. {}", user);

            return null;
        }
        return null;
    }

    /**
     *     1. go to here: https://login.microsoftonline.com/common/.well-known/openid-configuration
     *     2. check the value of "jwks_uri", which is "https://login.microsoftonline.com/common/discovery/keys"
     *     3. go to https://login.microsoftonline.com/common/discovery/keys
     *     4. get "kid" value from header, which is "Y4ueK2oaINQiQb5YEBSYVyDcpAU"
     *     5. search Y4ueK2oaINQiQb5YEBSYVyDcpAU in key file to get the key.
     *
     *     (We can manually decode JWT token at https://jwt.io/ by copy'n'paste)
     *     to select the public key used to sign this token.
     *     (There are about three keys which are rotated about everyday.)
     *
     * @throws IOException
     * @throws CertificateException
     */
     private PublicKey loadPublicKey(String soughtKid) {

        // Key Info (RSA PublicKey)
        String openidConfigStr = readUrl("https://login.microsoftonline.com/common/.well-known/openid-configuration");
        if (log.isDebugEnabled()) {
            log.debug("AAD OpenID Config: {}", openidConfigStr);
        }

        JSONObject openidConfig = new JSONObject(openidConfigStr);
        String jwksUri = openidConfig.getString("jwks_uri");
        if (log.isDebugEnabled()) {
            log.debug("AAD OpenID Config jwksUri: {}", jwksUri);
        }

        String jwkConfigStr = readUrl(jwksUri);
        if (log.isDebugEnabled()) {
            log.debug("AAD OpenID JWK Config: {}", jwkConfigStr);
        }

        JSONObject jwkConfig = new JSONObject(jwkConfigStr);
        JSONArray keys = jwkConfig.getJSONArray("keys");
        for (int i = 0; i < keys.length(); i++) {
            JSONObject key = keys.getJSONObject(i);

            String kid = key.getString("kid");
            if (!soughtKid.equals(kid)) {
                continue;
            }

            String keyStr = makePemCertificate(key);

            /*
             * go to https://jwt.io/ and copy'n'paste the jwt token to the left side, it will be decoded on the right side,
             * copy'n'past the public key (from ----BEGIN... to END CERT...) to the verify signature, it will show signature verified.
             */

            // read certification
            X509Certificate cer = null;
            try {
                CertificateFactory fact = CertificateFactory.getInstance("X.509");
                InputStream stream = new ByteArrayInputStream(keyStr.getBytes(StandardCharsets.US_ASCII));
                cer = (X509Certificate) fact.generateCertificate(stream);
                if (log.isTraceEnabled()) {
                    log.trace("AAD OpenID X509Certificate: {}", cer);
                }
            } catch (CertificateException e) {
                throw new RuntimeException(e);
            }

            // get public key from certification
            PublicKey publicKey = cer.getPublicKey();
            if (log.isDebugEnabled()) {
                log.debug("AAD OpenID X509Certificate publicKey: {}", publicKey);
            }

            return publicKey;
        }
        return null;
    }

    private String makePemCertificate(JSONObject key) {
        String x5c = key.getJSONArray("x5c").getString(0);
        String[] certParts = x5c.split("(?<=\\G.{64})");

        String keyStr = "-----BEGIN CERTIFICATE-----\r\n";
        keyStr += String.join("\r\n", certParts);
        keyStr += "-----END CERTIFICATE-----\r\n";

        if (log.isDebugEnabled()) {
            log.debug("AAD OpenID Key:\n{}", keyStr);
        }
        return keyStr;
    }

    //TODO: cache content to file to prevent access internet everytime.
    private String readUrl(String url) {
        try {
            URL addr = new URL(url);
            StringBuilder sb = new StringBuilder();
            try (BufferedReader in = new BufferedReader(new InputStreamReader(addr.openStream()))) {
                String inputLine = null;
                while ((inputLine = in.readLine()) != null) {
                    sb.append(inputLine);
                }
            }
            return sb.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private class OpenidSigningKeyResolver extends SigningKeyResolverAdapter {
        @Override
        public Key resolveSigningKey(JwsHeader header, Claims claims) {
            return loadPublicKey(header.getKeyId());
        }
    }
}