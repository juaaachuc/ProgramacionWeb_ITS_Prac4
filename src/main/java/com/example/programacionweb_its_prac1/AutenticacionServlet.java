package com.example.programacionweb_its_prac1;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.*;

import io.jsonwebtoken.*;
import org.mindrot.jbcrypt.BCrypt;

import javax.crypto.SecretKey;

@WebServlet("/autenticacion-servlet/*")

public class AutenticacionServlet extends HttpServlet {
    private static final String SECRET_KEY = "mWQKjKflpJSqyj0nDdSG9ZHE6x4tNaXGb35J6d7G5mo=";
    private static final Map<String, User> users = new HashMap<>();
    private final JsonResponse jResp = new JsonResponse();
    private final SecretKey key = Jwts.SIG.HS256.key().build();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("application/json");
        jResp.failed(req, resp, "404 - Recurso no encontrado", HttpServletResponse.SC_NOT_FOUND);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("application/json");
        if (req.getPathInfo() == null) {
            jResp.failed(req, resp, "404 - Recurso no encontrado", HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        String[] path = req.getPathInfo().split("/");

        if (req.getPathInfo().equals("/")) {
            jResp.failed(req, resp, "404 - Recurso no encontrado", HttpServletResponse.SC_NOT_FOUND);
        }

        String action = path[1];

        switch (action) {
            case "register":
                register(req, resp);
                break;
            case "login":
                login(req, resp);
                break;
            case "logout":
                logout(req, resp);
                break;
            default:
                jResp.failed(req, resp, "404 - Recurso no encontrado", HttpServletResponse.SC_NOT_FOUND);
        }
    }

    private void register(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String username = req.getParameter("username");
        String password = req.getParameter("password");
        String fullName = req.getParameter("fullName");
        String email = req.getParameter("email");

        if (username == null || password == null || fullName == null || email == null) {
            jResp.failed(req, resp, "Todos los campos son obligatorios", HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        // Encrypt the password (You should use a stronger encryption algorithm)
        String encryptedPassword = encryptPassword(password);
        User user = new User(fullName, email, username, encryptedPassword);

        users.put(username, user);

        jResp.success(req, resp, "Usuario creado con éxito", users);
    }

    private void login(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String username = req.getParameter("username");
        String password = req.getParameter("password");

        User user = users.get(username);

        if (user != null) {
            if (verifyPassword(password, user.getPassword())) {
                String token = Jwts.builder().
                        header().
                            keyId(SECRET_KEY).
                            and().
                        subject(username).
                        signWith( generalKey() ).
                        compact();

                jResp.success(req, resp, "Usuario encontrado y autenticado", token);
                return;
            }
        }

        jResp.failed(req, resp, "Nombre de usuario o contraseña inválidos", HttpServletResponse.SC_UNAUTHORIZED);
    }

    private void logout(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.getWriter().write("Logged out successfully");
    }

    private String encryptPassword(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }

    private boolean verifyPassword(String inputPassword, String storedPassword) {
        return BCrypt.checkpw(inputPassword, storedPassword);
    }

    public static SecretKey generalKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
