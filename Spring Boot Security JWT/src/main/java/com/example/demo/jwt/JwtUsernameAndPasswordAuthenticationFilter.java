/************ Login: Option 3**************************/
package com.example.demo.jwt;

import java.io.IOException;
import java.util.Date;
import java.time.LocalDate;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	
	private final AuthenticationManager authenticationManager;
	private final JwtConfig jwtConfig;
	private final SecretKey secretKey;

	public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager, JwtConfig jwtConfig, SecretKey secretKey) {
		super();
		this.authenticationManager = authenticationManager;
		this.jwtConfig = jwtConfig;
		this.secretKey = secretKey;
	}

	// 1. GEt Credentials from client and validate it
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request,
												HttpServletResponse response) throws AuthenticationException {
		try {
			// get the username and password from the input stream
		UsernameAndPasswordAuthenticationRequest authenticationRequest = new ObjectMapper().
				readValue(request.getInputStream(),UsernameAndPasswordAuthenticationRequest.class);
		
		Authentication authentication = new UsernamePasswordAuthenticationToken(
				authenticationRequest.getUsername(), authenticationRequest.getPassword()) ;
		
		//authenticationManager will check if the username exists once verified it will check the credential password
		Authentication authenticate = authenticationManager.authenticate(authentication);
		
		return authenticate;
		
		
		} catch(IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	// This method is executed if the attemptAuthentication was successful 
	// 2. in that case we send the JWT token to client
	@Override
	protected void successfulAuthentication(HttpServletRequest request, 
											HttpServletResponse response, 
											FilterChain chain,
											Authentication authResult) throws IOException, ServletException {
	
		String token = Jwts.builder()
							.setSubject(authResult.getName())
							.claim("authorities",authResult.getAuthorities())  // add manual map (key,value) to the body of token
							.setIssuedAt(new Date())
							//.setExpiration(java.sql.Date.valueOf(LocalDate.now().plusWeeks(2))) // 2 weeks
							.setExpiration(java.sql.Date.valueOf(LocalDate.now().plusDays(jwtConfig.getTokenExpirationAfterDays()))) // expiration from config file
							.signWith(secretKey)
							.compact();
			
			
		// add the token to the response Header
		response.addHeader(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix() + token);
	}

}
/************ END **************************/