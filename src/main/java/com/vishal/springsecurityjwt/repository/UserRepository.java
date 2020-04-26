package com.vishal.springsecurityjwt.repository;

import com.vishal.springsecurityjwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User,Integer> {

    User findAllByUsername(String username);
}
