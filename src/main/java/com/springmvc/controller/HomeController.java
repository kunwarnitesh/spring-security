package com.springmvc.controller;


import com.springmvc.entity.User;
import com.springmvc.entity.VerificationToken;
import com.springmvc.repositories.UserRepository;
import com.springmvc.repositories.VerificationTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import java.util.UUID;

@Controller
public class HomeController {

    @Autowired
    UserRepository userRepository;

    @Autowired
    VerificationTokenRepository verificationTokenRepository;

    @RequestMapping(value = "/")
    public String home() {
        return "home";
    }

    @RequestMapping(value = "/home")
    public String loadHome() {
        return "home";
    }

    @RequestMapping(value = "/login")
    public String login() {
        return "login";
    }

    @RequestMapping(value = "/register")
    public String register(){
        return "register";
    }


    @RequestMapping("/registerUser")
    public String registerUser(User user, HttpServletRequest httpServletRequest){
        /*userRepository.save(user);
        return "login";*/

        String token= UUID.randomUUID().toString();
        user.setEnabled(false);
        userRepository.save(user);
        String authUrl="http://"+httpServletRequest.getServerName()
                + ":"
                +httpServletRequest.getServerPort()
                + httpServletRequest.getContextPath()
                +"/registrationConfirmation"
                +"?token="+token;
        System.out.println(authUrl);

        VerificationToken verificationToken = new VerificationToken();
        verificationToken.setToken(token);
        verificationToken.setUser(user);
        verificationTokenRepository.save(verificationToken);

        return "login";
    }

    @RequestMapping("/registrationConfirmation")
    public String registrationConfirmation(String token){
        VerificationToken verificationToken = verificationTokenRepository.findByToken(token);
        User user =verificationToken.getUser();
        user.setEnabled(true);
        userRepository.save(user);
        return "redirect:/login";
    }
}
