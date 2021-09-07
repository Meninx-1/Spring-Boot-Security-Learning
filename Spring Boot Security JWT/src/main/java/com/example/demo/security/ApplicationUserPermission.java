package com.example.demo.security;

public enum ApplicationUserPermission {
	STUDENT_READ("student:read"),
	STUDENT_WRITE("student:write"),
	COURSE_READ("course:read"),
	COURSE_WRITE("couse:write");

	private String permission;
	
	ApplicationUserPermission(String permission) {
		this.permission=permission;
	}
	
	String getPermission() {
		return permission;
	}
	
}
