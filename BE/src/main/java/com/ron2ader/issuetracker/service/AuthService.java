package com.ron2ader.issuetracker.service;

import com.ron2ader.issuetracker.auth.github.GithubProperties;
import com.ron2ader.issuetracker.auth.github.GithubToken;
import com.ron2ader.issuetracker.auth.github.GithubTokenRequest;
import com.ron2ader.issuetracker.auth.github.GithubUserInfo;
import com.ron2ader.issuetracker.auth.jwt.JwtProvider;
import com.ron2ader.issuetracker.controller.memberdto.MemberDto;
import com.ron2ader.issuetracker.domain.member.Member;
import com.ron2ader.issuetracker.domain.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientException;

import java.util.NoSuchElementException;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final WebClient webClient;
    private final GithubProperties githubProperties;
    private final JwtProvider jwtProvider;
    private final MemberRepository memberRepository;

    public GithubToken requestAccessToken(String code) {
        if (code == null) {
            throw new IllegalArgumentException("요청 코드가 올바르지 않습니다.");
        }
        log.info("accesstokenurl={}", githubProperties.getAccessTokenUrl());
        log.info("code={}", code);
        return webClient.post()
                .uri(githubProperties.getAccessTokenUrl())
                .bodyValue(
                        GithubTokenRequest.of(githubProperties.getClientId(), githubProperties.getClientSecret(), code)
                )
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .bodyToMono(GithubToken.class)
                .block();
    }

    public GithubUserInfo requestUserInfo(GithubToken githubToken) {
        if (githubToken.getTokenType() == null || githubToken.getAccessToken() == null) {
            throw new IllegalArgumentException("github userInfo에 접근할 수 없습니다.");
        }

        log.info("githubToken={}", githubToken.toHeader());
        try {
            return webClient.get()
                    .uri("/user")
                    .header(HttpHeaders.AUTHORIZATION, githubToken.toHeader())
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .bodyToMono(GithubUserInfo.class)
                    .block();
        } catch (WebClientException webClientException) {
            throw new IllegalArgumentException("token이 올바르지 않습니다.");
        }

    }

    public MemberDto findUserByToken(String token) {
        if (!jwtProvider.validateToken(token)) {
            throw new RuntimeException(); // 예외처리 필요
        }
        String memberId = jwtProvider.getPayload(token);
        Member member = memberRepository.findByMemberId(memberId).orElseThrow(NoSuchElementException::new);

        return new MemberDto(member.getMemberId(), member.getAvatarUrl());
    }

}
