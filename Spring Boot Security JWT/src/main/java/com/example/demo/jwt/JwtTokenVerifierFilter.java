package com.example.demo.jwt;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.google.common.base.Strings;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

// This is inteded to be executed once per request after validation to verify the token
public class JwtTokenVerifierFilter extends OncePerRequestFilter{

    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    public JwtTokenVerifierFilter(JwtConfig jwtConfig, SecretKey secretKey) {
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }
    
	@Override
	protected void doFilterInternal(HttpServletRequest request, 
									HttpServletResponse response,
									FilterChain filterChain) throws ServletException, IOException {
		
		String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());
		
		if(Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())) {
			filterChain.doFilter(request, response);
			return;
		}
		
		// we grab the token without the first part "Bearer "
		String token = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "");
		
		try {
			
			
			//decrypt and validate the token received from client
			// 4. Validate the token
			Jws<Claims> claimsJws = Jwts.parser()
				.setSigningKey(secretKey)
				.parseClaimsJws(token);
			
			// Get the payload part = body  example: https://jwt.io
			Claims body = claimsJws.getBody();
			
			String username = body.getSubject();
			
			var authorities = (List<Map<String,String>>) body.get("authorities");	
			
			Set<SimpleGrantedAuthority> simpleGrantedAuthority = authorities.stream()
						.map(m -> new SimpleGrantedAuthority(m.get("authority")))
						.collect(Collectors.toSet());
				
			//// 5. Create auth object
			// UsernamePasswordAuthenticationToken: A built-in object, used by spring to represent the current authenticated / being authenticated user.
			// It needs a list of authorities, which has type of GrantedAuthority interface, where SimpleGrantedAuthority is an implementation of that interface
			
			Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, simpleGrantedAuthority);
			
			// After setting the Authentication in the context, we specify
			// that the current user is authenticated. So it passes the
			// Spring Security Configurations successfully.
			 // 6. Authenticate the user
			 // Now, user is authenticated
			SecurityContextHolder.getContext().setAuthentication(authentication);	
			
		} catch(JwtException e) {
			throw new IllegalStateException(String.format("Token %s: cannot be trusted", token));
		}
		
		// to pass the request and response to the filter chain
		filterChain.doFilter(request, response);
	}



}
