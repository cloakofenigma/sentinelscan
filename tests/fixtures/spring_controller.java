package com.example.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import javax.validation.Valid;

@RestController
@RequestMapping("/api")
public class UserController {

    // Missing input validation
    @PostMapping("/users")
    public User createUser(@RequestBody UserDTO dto) {
        return userService.create(dto);
    }

    // Has validation - safe
    @PostMapping("/users/safe")
    public User createUserSafe(@Valid @RequestBody UserDTO dto) {
        return userService.create(dto);
    }

    // Missing authorization on admin endpoint
    @DeleteMapping("/admin/users/{id}")
    public void deleteUser(@PathVariable Long id) {
        userService.delete(id);
    }

    // Properly secured
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/admin/safe/users/{id}")
    public void deleteUserSafe(@PathVariable Long id) {
        userService.delete(id);
    }

    // IDOR - direct object reference
    @GetMapping("/users/{id}")
    public User getUser(@PathVariable Long id) {
        return userService.findById(id);
    }
}
