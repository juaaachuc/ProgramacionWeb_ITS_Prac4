package com.example.programacionweb_its_prac1;

import com.google.gson.Gson;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Clase que se utiliza para crear un objeto JSON de respuesta
 */
public class JsonResponse {
    /**
     * Mensaje de respuesta
     */
    private String message;
    /**
     * Datos de respuesta
     */
    private Object data;
    /**
     * Código de respuesta
     */
    private int code;

    public JsonResponse() {}

    public void setResponse (String message, Object data, int code) {
        this.message = message;
        this.data = data;
        this.code = code;
    }

    /**
     * Método que se utiliza para enviar una respuesta exitosa.
     * @param req
     * @param resp
     * @param message Mensaje de respuesta
     * @param data Datos de respuesta
     * @throws IOException
     */
    public void success(HttpServletRequest req, HttpServletResponse resp, String message, Object data) throws IOException {
        Gson gson = new Gson();
        this.setResponse(message, data, HttpServletResponse.SC_OK);
        String json = gson.toJson(this);

        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setCharacterEncoding("UTF-8");
        resp.getWriter().write(json);
    }

    /**
     * Método que se utiliza para enviar una respuesta fallida.
     * @param req
     * @param resp
     * @param message Mensaje de respuesta
     * @param code Código de respuesta
     * @throws IOException
     */
    public void failed(HttpServletRequest req, HttpServletResponse resp, String message, int code) throws IOException {
        Gson gson = new Gson();
        this.setResponse(message, null, code);
        String json = gson.toJson(this);

        resp.setStatus(code);
        resp.setCharacterEncoding("UTF-8");
        resp.getWriter().write(json);
    }
}