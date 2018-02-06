package com.springmvc.repositories;

import com.springmvc.entity.VerificationToken;
import org.springframework.data.repository.CrudRepository;

public interface VerificationTokenRepository extends CrudRepository<VerificationToken,Integer> {

    public VerificationToken findByToken(String token);
}
