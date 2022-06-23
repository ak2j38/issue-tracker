package com.ron2ader.issuetracker.controller;

import com.ron2ader.issuetracker.auth.Login;
import com.ron2ader.issuetracker.auth.github.GithubToken;
import com.ron2ader.issuetracker.auth.github.GithubUserInfo;
import com.ron2ader.issuetracker.auth.jwt.JwtProvider;
import com.ron2ader.issuetracker.controller.authdto.Tokens;
import com.ron2ader.issuetracker.controller.memberdto.MemberDto;
import com.ron2ader.issuetracker.domain.member.Member;
import com.ron2ader.issuetracker.service.AuthService;
import com.ron2ader.issuetracker.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.Optional;

@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService githubOAuthService;
    private final MemberService memberService;
    private final JwtProvider jwtProvider;

    @GetMapping("/auth/github")
    public Tokens requestAccessToken(String code) {
        log.info("controller code={}", code);
        GithubToken githubToken = Optional.ofNullable(githubOAuthService.requestAccessToken(code))
                .orElseThrow(() -> new IllegalArgumentException("code가 잘못되었습니다."));
        log.info("githubtoken={}, {}, {}", githubToken, githubToken.getAccessToken(), githubToken.getTokenType());
        GithubUserInfo githubUserInfo;
        try {
            githubUserInfo = githubOAuthService.requestUserInfo(githubToken);
        } catch (WebClientResponseException webClientResponseException) {
            throw new IllegalArgumentException("code가 잘못되었습니다.");
        }


        Member member = memberService.upsert(Member.of(githubUserInfo.getUserId(), githubUserInfo.getAvatarUrl()));

        String accessToken = jwtProvider.generateAccessToken(member.getMemberId());
        String refreshToken = jwtProvider.generateRefreshToken(member.getMemberId());

        return Tokens.of(accessToken, refreshToken);
    }

    @GetMapping("/auth/refresh")
    public Tokens requestNewTokens(@Login MemberDto memberDto) {
        MemberDto findMember = memberService.findMember(memberDto.getMemberId());

        String accessToken = jwtProvider.generateAccessToken(findMember.getMemberId());
        String refreshToken = jwtProvider.generateRefreshToken(findMember.getMemberId());

        return Tokens.of(accessToken, refreshToken);
    }
}
