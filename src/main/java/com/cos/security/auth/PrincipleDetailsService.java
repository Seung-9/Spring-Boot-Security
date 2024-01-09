package com.cos.security.auth;

import com.cos.security.model.User;
import com.cos.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


/**
 * 시큐리티 설정에서 loginProcessingUrl("/login") 을 걸어놨기 때문에
 * login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC 되어있는 loadUserByUsername 함수가 실행
 */
@Service
public class PrincipleDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    // security session 에는 Authentication 타입이 들어와야됨
    // Authentication 에는 UserDetails 타입이 들어와야됨
    // 이 메서드가 위에 동작을 다 해줌
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("username:" + username);
        User userEntity = userRepository.findByUsername(username);
        if (username != null) {
            return new PrincipleDetails(userEntity);
        }
        return null;
    }
}
