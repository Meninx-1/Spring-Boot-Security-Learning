package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.example.demo.auth.ApplicationUserService;
import com.example.demo.jwt.JwtConfig;
import com.example.demo.jwt.JwtTokenVerifierFilter;
import com.example.demo.jwt.JwtUsernameAndPasswordAuthenticationFilter;

import static com.example.demo.security.ApplicationUserRole.*;

import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import static com.example.demo.security.ApplicationUserPermission.*;

//The @EnableWebSecurity annotation is crucial if we disable the default security configuration.
//a. Annotate with @EnableWebSecurity, which will apply the class to the global WebSecurity
@Configuration
@EnableWebSecurity
/************ Authorize: Option 1*******************/
// this is to activate the security in methods
//EnableGlobalMethodSecurity provides AOP security on methods. Some of the annotations that it provides are
//PreAuthorize , PostAuthorize .
//prePostEnabled = true => This enables processing of @PreAuthorize/@PreFilter and @PostAuthorize/@PostFilter
@EnableGlobalMethodSecurity(prePostEnabled = true)
/************ END *******************/
//b. Extend WebSecurityConfigurerAdapter, which provides you a configuration methods,
//and can be used to specify what URIs to protect or pass through.
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final PasswordEncoder passwordEncoder;
	private final ApplicationUserService applicationUserService;
	private final SecretKey secretKey;
	private final JwtConfig jwtConfig;
	
    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, 
    								ApplicationUserService applicationUserService,
    								JwtConfig jwtConfig, 
    								SecretKey secretKey) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }
    
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http	    
				//CSRF stands for Cross-Site Request Forgery.
				//It is an attack that forces an end user to execute unwanted actions on a web application 
				//in which they are currently authenticated
				// if CSRF is enabled only GET request is working and the other POST PUT DELETE ...
				// for more : //https://docs.spring.io/spring-security/site/docs/5.0.x/reference/html/csrf.html
				/************ CSRF: Option 1*******************/
		 		.csrf().disable() // to disable the csrf in order to be able to run POST and PUT and DELETE without problem
				/************ END *******************/
				
				/************ CSRF: Option 2*******************/
				// we are going now to enable csrf
				//.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) // to see the XSRF-TOKEN in Postman uncomment the 2 lines
				//.and()
				/************ END *******************/
		 		
		 		/************ Login: Option 3**************************/
		 		/*  Stateless, in this context, means that we don't store any information about the logged-in
		 		 *  user in memory. We still need to store information about the logged-in user somewhere and associate it with a client
		 		 */
		 		.sessionManagement()
		 			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		 		.and()
		 		.addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
		 		//register and create JwtTokenVerifierFilter after the JwtUsernameAndPasswordAuthenticationFilter
		 		.addFilterAfter(new JwtTokenVerifierFilter(jwtConfig,secretKey), JwtUsernameAndPasswordAuthenticationFilter.class)
		 		/************ END *******************/
		
				.authorizeRequests() //authorizeRequests() Allows restricting access based upon the HttpServletRequest using RequestMatcher implementations.
				
				// the order of antMatchers matters it is processed one by one in order of evocation for every request
				.antMatchers("/","/index","/css/*","/js/*").permitAll() // permit all the pattern defined: any user can access it without authentication
				.antMatchers("/api/**").hasRole(STUDENT.name())
				
				/************ Authorize: Option 1*******************/
				/*
				 * You can use the @PreAuthorize annotation instead of the below code in order to authorize method 
				 * directly where there is @GetMapping, post, delete ...
				 * in that case you need to add @EnableGlobalMethodSecurity in the Security config class in our case this class

				.antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
				.antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
				.antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
				.antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
				*/
				/************ END *******************/
				
				.anyRequest()     // will restrict the access for any other endpoint, 
				.authenticated();  //and the user must be authenticated.
							
				
				/************ Login: Option 1**************************/
				//.and()
				//.httpBasic(); // Use Basic authentication
				 /**************End ************************/
				 
				/************ Login: Option 2**************************/
				//.and()
//				.formLogin() // use Form based Authentication
//				    .loginPage("/login")// set url to send users for login - if we stop here we cannot get the login page unless it is permitted
//				    .permitAll()
//				/*If the always-use-default-target attribute is set to true, then the user is always
//				 *  redirected to this page. If that attribute is set to false, 
//				 *  then the user will be redirected to the previous page they wanted to visit before 
//				 *  being prompted to authenticate.
//				 */
//				    .defaultSuccessUrl("/courses",true)
//				    .passwordParameter("password") // this is the name of the input name for password in login.html
//				    .usernameParameter("username")
//				.and()
//				/*
//				 * Remember me is a feature that allows a user to access into application without re-login. 
//				 * User's login session terminates after CLOSING THE BROWSER and if user again access 
//				 * the application by opening browser, it prompts for login.
//				 * But we can avoid this re-login by using remember me feature.
//				 *  It stores user's identity into the Cookie or database and use to identity the user
//				 */
//				.rememberMe() // remember the validated sessionId for 2 weeks of inactivity by default if we stop here	
//				   .rememberMeParameter("remember-me")
//				   .tokenValiditySeconds((int)TimeUnit.SECONDS.toSeconds(5*60)) // 5 * 60s
//				   .key("somethingverysecure")
//				   
//				.and()
//				.logout()
//					.logoutUrl("/logout")
//					// if we disable csrf it is recommended to use the below line
//					//in case the csrf is enable it is recommended to use POST for logout and delete the below line
//					//https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/annotation/web/configurers/LogoutConfigurer.html#logoutUrl(java.lang.String)
//					.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
//					.clearAuthentication(true)
//					.invalidateHttpSession(true)
//					.deleteCookies("JSESSIONID","remember-me")
//					.logoutSuccessUrl("/login");
		
		           /******************** END ******************/
				   
	}
	
	// This is if users are stored in database like Postgres 
	/********************Users Definition: Option 1******************/
	// to wire the bean created of DaoAuthenticationProvider
	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthenticationProvider());
	}
	// Create the Bean
	@Bean 
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(applicationUserService);
		return provider;
	}
	
	/*******************END*******************/
	
	
//	// This is how you create users and store them in-memory database
	/***************** Users Definition: Option 2 *********************/
//	@Override
//	@Bean
//	protected UserDetailsService userDetailsService() {
//		
//		// We create our users 
//		UserDetails annaSmithUser = User.builder()
//			.username("annasmith")
//			.password(passwordEncoder.encode("password")) // we must use password encoder so spring can login in basic auth
//			//.roles(STUDENT.name()) // ROLE_STUDENT
//			.authorities(STUDENT.getGrantedAuthorities())
//			.build();	
//		
//		UserDetails lindaUser = User.builder()
//				.username("linda")
//				.password(passwordEncoder.encode("password123")) // we must use password encoder so spring can login 
//				//.roles(ADMIN.name()) // ROLE_ADMIN
//				.authorities(ADMIN.getGrantedAuthorities())
//				.build();
//		
//		UserDetails tomUser = User.builder()
//				.username("tom")
//				.password(passwordEncoder.encode("password123")) // we must use password encoder so spring can login 
//				//.roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE this is only to define role without permissions
//				.authorities(ADMINTRAINEE.getGrantedAuthorities())  // this way to define both role and its defined permissions
//				.build();
//		
//		// We save them in in memory database
//		return new InMemoryUserDetailsManager(
//				annaSmithUser,
//				lindaUser,
//				tomUser);
//			
//	}
     /******************END ********************/

	
	
}

/*
Basic Auth
=============
the authorization base64 username+password is included in header for every reqest 
https is recommended for that 
simple and fast 
but once logged in you cannot logout

Form Based Authentication
===================
username and password
standard in most websites
forms(full control) on how you want to style your form login panel
can logout
https recommended

JWT : Json Web Token 
===================
+Fast
+Stateless
+Used across many services

-Compromised Secret Key
-No visibility to logged in users 
-Token can be stolen
*/
