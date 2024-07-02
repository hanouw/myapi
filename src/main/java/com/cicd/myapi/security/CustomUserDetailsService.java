package com.cicd.myapi.security;

import com.cicd.myapi.domain.Member;
import com.cicd.myapi.dto.MemberUserDetail;
import com.cicd.myapi.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;
    
    // usename(email)로 회원 정보 DB에서 조회 -> memberDto(UserDetails타입)으로 변환해 리턴
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 매개변수 username (시큐리티 명칭) == email (우리 Member의 변수명)
        log.info("************* CustomUserDetailsService.java / method name : loadUserByUsername / username : {}", username);
        Member member = memberRepository.getMemberWithRoles(username);
        if(member == null){
            throw new UsernameNotFoundException("Email(username) Not Found");
        }
        MemberUserDetail memberDTO = new MemberUserDetail(member.getEmail(),
                member.getPassword(),
                member.getNickname(),
                member.isSocial(),
                member.getRoleList().stream()
                        .map(role -> role.name())
                        .collect(Collectors.toList()));
        log.info("************* CustomUserDetailsService.java / method name : loadUserByUsername / memberDTO : {}", memberDTO);
        return memberDTO;
    }
}
