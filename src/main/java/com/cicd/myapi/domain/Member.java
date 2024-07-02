package com.cicd.myapi.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Member {

    @Id
    private String email;
    private String password;
    private String nickname;
    private boolean social;

    @ElementCollection
    @Builder.Default
    @Enumerated(EnumType.STRING)
    private List<Role> roleList = new ArrayList<>();

    // 월드 수정 메서드
    public void changeNickname(String nickname) { this.nickname = nickname; }
    public void changePassword(String password) { this.nickname = password; }
    public void changeSocial(boolean social) { this.social = social; }

    // 권한 추가
    public void addRole(Role role) { roleList.add(role); }

    // 권한 모두 삭제
    public void clearRole() { roleList.clear(); }

}
