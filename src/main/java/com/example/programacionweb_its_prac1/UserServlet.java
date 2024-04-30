package com.example.programacionweb_its_prac1;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.*;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.Base64;

import static com.example.programacionweb_its_prac1.AutenticacionServlet.generalKey;

@WebServlet("/user-servlet/*")
public class UserServlet extends HttpServlet {
    private final SecretKey key = Jwts.SIG.HS256.key().build();
    private final JsonResponse jResp = new JsonResponse();
    private static final String SECRET_KEY = "mWQKjKflpJSqyj0nDdSG9ZHE6x4tNaXGb35J6d7G5mo=";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("application/json");
        String authTokenHeader = req.getHeader("Authorization");
        validateAuthToken(req, resp, authTokenHeader.split(" ")[1]);
    }

    private void validateAuthToken (HttpServletRequest req, HttpServletResponse resp, String token) throws IOException {
        String[] chunks = token.split("\\.");

        Base64.Decoder decoder = Base64.getUrlDecoder();

        String header = new String(decoder.decode(chunks[0]));
        String payload = new String(decoder.decode(chunks[1]));

        JwtParser jwtParser = Jwts.parser()
                .verifyWith( generalKey() )
                .build();
        try {
            jwtParser.parse(token);
            jResp.success(req, resp, "Autenticación probada", null);
        } catch (Exception e) {
            System.out.println(token);
            jResp.failed(req, resp, "Unathorized: " + e.getMessage(), 401);
        }
    }
}
