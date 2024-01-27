package com.cos.security.controller;

import com.cos.security.auth.PrincipalDetails;
import com.cos.security.model.User;
import com.cos.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder encoder;

    @ResponseBody
    @GetMapping("/test/login")
    public String testLogin(Authentication authentication,
                            @AuthenticationPrincipal PrincipalDetails userDetails) {
        System.out.println("/test/login ============");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        // 둘 다 같은 정보를 가짐
        System.out.println("authentication : " + principalDetails.getUser());
        System.out.println("UserDetails : " + userDetails.getUser());
        return "세션 정보 확인하기";
    }

    /**
     * 구글 로그인 할 때는 Oauth2User 로 받아야됨
     */
    @ResponseBody
    @GetMapping("/test/oauth/login")
    public String testLogin(Authentication authentication,
                            @AuthenticationPrincipal OAuth2User oauth) {
        System.out.println("/test/login ============");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        // 둘 다 같은 정보를 가짐
        System.out.println("authentication : " + oAuth2User.getAttributes());
        System.out.println("UserDetails : " + oauth.getAttributes());
        return "OAuth 세션 정보 확인하기";
    }

    @GetMapping({"", "/"})
    public String index() {
        return "index";
    }

    @GetMapping("/user")
    @ResponseBody
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println("principalDetails : " + principalDetails.getUser().getUsername());
        return "user";
    }

    @GetMapping("/admin")
    @ResponseBody
    public String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    @ResponseBody
    public String manager() {
        return "manager";
    }

    @GetMapping("/loginForm")
    public String login() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        user.setRole("ROLE_USER");
        String plainPassword = user.getPassword();
        String encodePassword = encoder.encode(plainPassword);
        user.setPassword(encodePassword);
        userRepository.save(user);
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    @ResponseBody
    public String info() {
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") // Secured 를 여러 개 걸고싶으면 이렇게 하면 됨
    @GetMapping("/data")
    @ResponseBody
    public String data() {
        return "데이터정보";
    }
}
