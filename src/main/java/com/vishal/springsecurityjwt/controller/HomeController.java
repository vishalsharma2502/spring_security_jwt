package com.vishal.springsecurityjwt.controller;

import com.vishal.springsecurityjwt.model.JwtRequest;
import com.vishal.springsecurityjwt.model.JwtResponse;
import com.vishal.springsecurityjwt.model.User;
import com.vishal.springsecurityjwt.service.UserService;
import com.vishal.springsecurityjwt.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
public class HomeController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserService userService;

    @Autowired
    JwtTokenUtil jwtTokenUtil;

    @GetMapping("/hello")
    public String Hello(){
        return "Hello World!!!!";
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticateToken(@RequestBody JwtRequest authenticateRequest) throws Exception {
        authenticate(authenticateRequest.getUsername(),authenticateRequest.getPassword());

        final UserDetails userDetails = userService.loadUserByUsername(authenticateRequest.getUsername());
        final String jwt = jwtTokenUtil.generateToken(userDetails);

        return ResponseEntity.ok(new JwtResponse(jwt));
    }

    private void authenticate(String username, String password) throws Exception{
        try{
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username,password));
        } catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody User user){
        return ResponseEntity.ok(userService.createUser(user));
    }
}
