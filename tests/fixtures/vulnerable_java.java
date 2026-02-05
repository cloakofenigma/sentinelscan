package com.example.app;

import java.io.*;
import java.sql.*;
import javax.servlet.http.*;

public class UserController {

    // SQL Injection via string concatenation
    public User getUser(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection(DB_URL);
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id=" + userId);
        return mapUser(rs);
    }

    // Path Traversal
    public byte[] downloadFile(String filename) throws IOException {
        File file = new File("/uploads/" + filename);
        return java.nio.file.Files.readAllBytes(file.toPath());
    }

    // Hardcoded password
    private String adminPassword = "SuperSecret123!";

    // Command injection
    public String runReport(String reportName) throws IOException {
        Runtime.getRuntime().exec("generate-report " + reportName);
        return "Report generated";
    }

    // Safe method - parameterized query
    public User getUserSafe(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection(DB_URL);
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id=?");
        stmt.setString(1, userId);
        return mapUser(stmt.executeQuery());
    }
}
