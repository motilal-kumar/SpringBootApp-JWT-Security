package com.neosoft.springbootsecurityoauth2.controller;


import com.neosoft.springbootsecurityoauth2.entity.Student;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {



    private static final List<Student> STUDENTS = Arrays.asList(

            new Student(1, "Motilal Kumar"),
            new Student(2, "Pankaj Udas"),
            new Student(3, "Raja Babu")
    );

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRANEE')")
    public  List<Student>   getAllStudents(){

        System.out.println("getAllStudents");

        return STUDENTS;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void registerNewStudent(@RequestBody  Student student){

        System.out.println("registerNewStudent");

        System.out.println("student:"+student);

    }

    @DeleteMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void deleteStudent(@PathVariable("studentId") Integer studentId){
        System.out.println("deleteStudent");

        System.out.println("studentId:"+studentId);

    }


    @PutMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student){
        System.out.println("updateStudent");

        System.out.println(String.format("%s %s",studentId, student));

    }


}
