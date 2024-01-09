package com.cos.security.auth;

import com.cos.security.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;


// 시큐리티가 /login 을 낚아채서 로그인을 진행 시킴
// 로그인을 진행이 완료되면 시큐리티가 가지는 session 을 만들어줌 ( Security ContextHolder 라는 키값에다가 세션 정보를 저장시킴)
// 오브젝트 => Authentication 타입 객체만 들어올 수 있음
// Authentication 안에 User 정보가 있어야됨.
// User 오브젝트의 타입 => UserDetails 타입 객체여야함

// 쉽게 말해서
// 시큐리티가 가지고 있는 세션 영역에 세션 정보를 저장해주는데 여기 들어갈 수 있는 객체가 Authentication 객체.
// Authentication 객체에 User 정보를 저장할 때 UserDetails 타입이어야함
// Security Session => Authentication => UserDetails(PricipleDetails)

public class PrincipleDetails implements UserDetails {

    private User user;

    public PrincipleDetails(User user) {
        this.user = user;
    }

    /**
     * 해당 User 의 권한을 return
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        // 1년동안 로그인 안 하면 -> 휴먼 계정
        // User 객체에 로그인 날짜를 기록하고, 로그인 날짜
        // 현재 시간 - 로그인 시간 이 1년을 초과하면 return false; 해주면 됨
        return true;
    }
}
