package com.example.demo.student;

import java.util.Arrays;
import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

	private static List<Student> STUDENTS = (List<Student>) Arrays.asList(
			new Student(1,"James Bond"),
			new Student(2,"Maria Jones"),
			new Student(3,"Anna Smith")     );
	
	@GetMapping // this should be added because the RequestMapping seems not having default method mapping
	//hasRole('ROLE_XXX') hasAnyRole('ROLE_XXX') hasAuthority('permission') hasAnyAuthority('permission')
	/************ Authorize: Option 2*******************/
	@PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_ADMINTRAINEE')")
	public List<Student> getAllStudents() {
		System.out.println("getAllStudents");
		return STUDENTS;
	}
	
	@PostMapping
	/************ Authorize: Option 2*******************/
	@PreAuthorize("hasAuthority('student:write')")
	/************ END *******************/
	public void registerNewStudent(@RequestBody Student student) {
		System.out.println("registerNewStudent");
		System.out.println(student);	
	}
	
	@DeleteMapping(path="{studentId}")
	/************ Authorize: Option 2*******************/
	@PreAuthorize("hasAuthority('student:write')")
	/************ END *******************/
	public void deleteStudent(@PathVariable("studentId") Integer studentId) {
		System.out.println("deleteStudent");
		System.out.println(studentId);
	}
	
	@PutMapping(path="{studentId}")
	/************ Authorize: Option 2*******************/
	@PreAuthorize("hasAuthority('student:write')")
	/************ END *******************/
	public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student) {
		System.out.println("updateStudent");
		System.out.println(String.format("%s %s", studentId, student));
		
	}

}
