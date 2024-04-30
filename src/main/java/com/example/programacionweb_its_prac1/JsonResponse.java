package com.example.programacionweb_its_prac1;

import com.google.gson.Gson;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public class JsonResponse {
    private String message;
    private Object data;
    private int code;

    public JsonResponse() {}

    public void setResponse (String message, Object data, int code) {
        this.message = message;
        this.data = data;
        this.code = code;
    }

    public void success(HttpServletRequest req, HttpServletResponse resp, String message, Object data) throws IOException {
        Gson gson = new Gson();
        this.setResponse(message, data, HttpServletResponse.SC_OK);
        String json = gson.toJson(this);

        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setCharacterEncoding("UTF-8");
        resp.getWriter().write(json);
    }

    public void failed(HttpServletRequest req, HttpServletResponse resp, String message, int code) throws IOException {
        Gson gson = new Gson();
        this.setResponse(message, null, code);
        String json = gson.toJson(this);

        resp.setStatus(code);
        resp.setCharacterEncoding("UTF-8");
        resp.getWriter().write(json);
    }
}