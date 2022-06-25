package com.ron2ader.issuetracker.controller.memberdto;

import com.ron2ader.issuetracker.domain.member.Member;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

@AllArgsConstructor
@Getter
@ToString
public class MemberDto {

    private String memberId;
    private String avatarUrl;

    public static MemberDto from(Member member) {
        return new MemberDto(member.getMemberId(), member.getAvatarUrl());
    }
}
