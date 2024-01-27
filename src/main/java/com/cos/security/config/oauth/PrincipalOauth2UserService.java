package com.cos.security.config.oauth;

import com.cos.security.auth.PrincipalDetails;
import com.cos.security.model.User;
import com.cos.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private UserRepository userRepository;

    // 구글로부터 받은 userRequest 데이터에 대한 후처리 되는 함수 ( 구글 로그인 정보들이 리턴됨 )
    // 함수 종료 시 @AuthenticationPrincipal 어노테이션이 만들어짐.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("getClientRegistration : " + userRequest.getClientRegistration()); // registration 으로 어떤 OAuth 로 로그인 했는지 확인 가능
        System.out.println("getAccessToken : " + userRequest.getAccessToken());

        OAuth2User oauth2User = super.loadUser(userRequest);
        // 구글 로그인을 클릭 -> 구글 로그인 창 -> 로그인 완료 -> code 를 리턴 ( OAuth-Client 라이브러리 ) -> Access Token 요청
        // 여기까지가 userRequest 정보 -> loadUser 함수 호출 -> 구글로부터 회원 프로필을 받아줌.
        System.out.println("getAttribute : " + oauth2User.getAttributes());

        // 회원가입 강제로 진행
        String provider = userRequest.getClientRegistration().getRegistrationId(); // google
        String providerId = oauth2User.getAttribute("sub");
        String username = provider + "_" + providerId; // google_103206529884151503288
        String email = oauth2User.getAttribute("email");
        String role = "ROLE_USER";

        User user = userRepository.findByUsername(username);
        if (user == null) { // 유저가 존재하지 않으면
            user = User.builder()
                    .username(username)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(user);
        }

        return new PrincipalDetails(user, oauth2User.getAttributes()); // 일반 로그인 하면 user, oauth2 로그인하면 oauth2User 정보가 들어감
    }
}
