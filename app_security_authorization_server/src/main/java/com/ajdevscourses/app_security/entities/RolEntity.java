package com.ajdevscourses.app_security.entities;

import jakarta.persistence.*;
import lombok.Data;

import java.math.BigInteger;
import java.util.BitSet;

@Entity
@Table(name = "roles")
@Data
public class RolEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private BigInteger id;
    @Column(name = "role_name")
    private String name;
    private String description;


}
