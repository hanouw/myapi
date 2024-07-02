package com.cicd.myapi.service;

import com.cicd.myapi.domain.Member;
import com.cicd.myapi.dto.MemberModifyDTO;
import com.cicd.myapi.dto.MemberUserDetail;
import org.springframework.transaction.annotation.Transactional;

import java.util.stream.Collectors;

@Transactional
public interface MemberService {


    // 카카오 회원 정보 요청
    MemberUserDetail getKakaoMember(String accessToken);

    void modifyMember(MemberModifyDTO memberModifyDTO);

    // Member Entity -> MemberDTO
    default MemberUserDetail entityToDTO(Member member) {
        return new MemberUserDetail(
                member.getEmail(),
                member.getPassword(),
                member.getNickname(),
                member.isSocial(),
                member.getRoleList().stream().map(role -> role.name()).collect(Collectors.toList())
        );
    }
}
