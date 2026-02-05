package com.example.app;

import java.sql.*;
import java.util.List;
import java.util.ArrayList;

public class SafeService {

    public User findUser(String userId) throws SQLException {
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        stmt.setString(1, userId);
        return mapUser(stmt.executeQuery());
    }

    public List<String> getItems() {
        List<String> items = new ArrayList<>();
        items.add("item1");
        items.add("item2");
        return items;
    }

    public int calculateTotal(int a, int b) {
        return a + b;
    }
}
