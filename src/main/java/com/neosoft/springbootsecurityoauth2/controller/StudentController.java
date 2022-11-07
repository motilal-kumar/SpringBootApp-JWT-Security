package com.neosoft.springbootsecurityoauth2.controller;

import com.neosoft.springbootsecurityoauth2.entity.Student;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {


    private static final List<Student>  STUDENTS = Arrays.asList(

        new Student(1, "Motilal Kumar"),
        new Student(2, "Pankaj Udas"),
        new Student(3, "Raja Babu")
    );

    @GetMapping(path = "{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId){

        return STUDENTS.stream().filter(student -> studentId.equals(student.getStudentId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Student "+studentId + "Does not exists!"));
    }
}
