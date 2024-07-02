package com.cicd.myapi.service;

import com.cicd.myapi.domain.Member;
import com.cicd.myapi.domain.Role;
import com.cicd.myapi.dto.MemberModifyDTO;
import com.cicd.myapi.dto.MemberUserDetail;
import com.cicd.myapi.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.LinkedHashMap;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class MemberServiceImpl implements MemberService{
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public MemberUserDetail getKakaoMember(String accessToken) {

        String email = getEmailFromKakaoAccessToken(accessToken);

        log.info("************* MemberServiceImpl.java / method name : getKakaoMember / email : {}", email);

        // DB에 회원이 있는지 조회
        Optional<Member> findMember = memberRepository.findById(email);

        // 기존 회원 -> 로그인
        if(findMember.isPresent()){
            MemberUserDetail MemberUserDetail = entityToDTO(findMember.get());
            return MemberUserDetail;
        }

        // 회원이 아닌 경우 -> 회원 추가
        // 임시 비번으로 회원 DB에 추가, 해당 정보로 MemberUserDetail 리턴
        Member socialMember = makeSocialMember(email);
        memberRepository.save(socialMember); // DB에 저장
        MemberUserDetail MemberUserDetail = entityToDTO(socialMember); // DTO변환해 리턴

        return MemberUserDetail;
    }

    @Override
    public void modifyMember(MemberModifyDTO memberModifyDTO) {
        Member member = memberRepository.findById(memberModifyDTO.getEmail()).orElseThrow();
        member.changePassword(passwordEncoder.encode(memberModifyDTO.getPassword()));
        member.changeSocial(false);
        member.changeNickname(memberModifyDTO.getNickname());
        memberRepository.save(member);
    }

    private Member makeSocialMember(String email) {
        // 임시 비번 만들어서 Member 엔티티 생성해 리턴
        String tmpPassword = makeTempPassword();
        log.info("************* MemberServiceImpl.java / method name : makeSocialMember / tmpPassword : {}", tmpPassword);
        String nickname = "SocialMember";
        Member member = Member.builder()
                .email(email)
                .password(passwordEncoder.encode(tmpPassword))
                .nickname(nickname)
                .social(true)
                .build();
        member.addRole(Role.USER);
        return member;
    }

    // 임시 비번 만들어주는 메서드
    private String makeTempPassword() {
        // char 한글자씩 랜덤으로 누적 추가해서 문자열 만들어주기
        StringBuffer stringBuffer = new StringBuffer();
        for(int i = 0; i < 10; i++) {
            stringBuffer.append((char)((int)(Math.random() * 55) + 65));
        }

        return stringBuffer.toString();
    }

    private String getEmailFromKakaoAccessToken(String accessToken) {
        // 카카오 사용자 정보 요청
        String kakaoGetUserURL = "https://kapi.kakao.com/v2/user/me";

        if(accessToken == null){
            throw new RuntimeException("Access Token is null");
        }

        // 카카오 서버에 RestTemplate 으로 사용자 정보 HTTP 요청
        RestTemplate restTemplate = new RestTemplate();
        // 헤더정보 생성
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + accessToken);
        headers.add("Content-type", "application/x-www-urlencoded;charset=utf-8");
        // 헤더 정보를 포함한 HttpEntity로 요청 객체 만들기 ( request )
        HttpEntity<String> entity = new HttpEntity<>(headers);

        // 요청 경로 생성해주는 클래스 이용
        UriComponents uriBuild = UriComponentsBuilder.fromHttpUrl(kakaoGetUserURL).build();

        // RestTemplate의 exchange() 메서드를 이용해 요청 보내기 -> 리턴은 Map
        ResponseEntity<LinkedHashMap> response = restTemplate.exchange(uriBuild.toString(), HttpMethod.GET, entity, LinkedHashMap.class);
        log.info("************* MemberServiceImpl.java / method name : getEmailFromKakaoAccessToken / response : {}", response);

        // Body에서 응답데이터 꺼내기
        LinkedHashMap<String, LinkedHashMap> body = response.getBody();
        log.info("************* MemberServiceImpl.java / method name : getEmailFromKakaoAccessToken / body : {}", body);

        // 응답 내용 중 카카오 계정 정보 꺼내기
        LinkedHashMap<String, String> kakaoAccount = body.get("kakao_account");
        log.info("************* MemberServiceImpl.java / method name : getEmailFromKakaoAccessToken / kakaoAccount : {}", kakaoAccount);

        return kakaoAccount.get("email"); // 이메일만 꺼내서 리턴
    }
}
