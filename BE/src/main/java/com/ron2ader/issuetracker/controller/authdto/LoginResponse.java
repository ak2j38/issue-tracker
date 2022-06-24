package com.ron2ader.issuetracker.controller.authdto;

import com.ron2ader.issuetracker.controller.memberdto.MemberDto;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(staticName = "of")
@Getter
public class LoginResponse {

    private final MemberDto loginMember;
    private final Tokens tokens;

}
