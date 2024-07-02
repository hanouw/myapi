package com.cicd.myapi.dto;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.*;
import java.util.stream.Collectors;

public class MemberUserDetail extends User {

    private String email;
    private String password;
    private String nickname;
    private boolean social;
    private List<String> roleNames = new ArrayList<>();

    public MemberUserDetail(String email, String password, String nickname, boolean social, List<String> roleNames) {
        super(email, password, roleNames.stream()
                .map(roleName -> new SimpleGrantedAuthority("ROLE_" + roleName))
                .collect(Collectors.toList())); // 시큐리티를 위한 부모 생성자 호출
        // 위 변수값 초기화
        this.email = email;
        this.password = password;
        this.nickname = nickname;
        this.social = social;
        this.roleNames = roleNames;
    }

    public Map<String, Object> getClaims() {
        Map<String, Object> map = new HashMap<>();
        map.put("email", email);
        map.put("password", password); // 비번은 나중에 전달 안하는 것으로 변경. 지금은 확인차 추가
        map.put("nickname", nickname);
        map.put("social", social);
        map.put("roleNames", roleNames); // List<String> 타입
        return map;
    }

}
