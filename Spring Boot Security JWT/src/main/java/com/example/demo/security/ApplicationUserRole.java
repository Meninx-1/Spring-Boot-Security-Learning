package com.example.demo.security;

import com.google.common.collect.Sets;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static com.example.demo.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
	STUDENT(Sets.newHashSet()),
	ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_WRITE, STUDENT_READ)),
	ADMINTRAINEE(Sets.newHashSet(COURSE_READ, STUDENT_READ));

	
	private Set<ApplicationUserPermission> permissions;

	private ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
		this.permissions = permissions;
	}

	public Set<ApplicationUserPermission> getPermissions() {
		return permissions;
	}
	
	public Set<SimpleGrantedAuthority> getGrantedAuthorities() {
		Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
		// we created permission based on getPermission() value so we need to invoke the same
		//thing in the antMatcher.hasAuthority
						.map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
						.collect(Collectors.toSet());
		
		permissions.add(new SimpleGrantedAuthority("ROLE_"+this.name()));
		return permissions;
	}
}
