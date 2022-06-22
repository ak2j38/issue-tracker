package com.ron2ader.issuetracker.service;

import com.ron2ader.issuetracker.controller.issuedto.IssueCondition;
import com.ron2ader.issuetracker.controller.issuedto.IssueDetail;
import com.ron2ader.issuetracker.controller.issuedto.IssueDetailResponse;
import com.ron2ader.issuetracker.controller.issuedto.IssueSimpleResponse;
import com.ron2ader.issuetracker.controller.memberdto.MemberDto;
import com.ron2ader.issuetracker.domain.issue.Issue;
import com.ron2ader.issuetracker.domain.issue.IssueRepository;

import java.util.NoSuchElementException;

import com.ron2ader.issuetracker.domain.member.Member;
import com.ron2ader.issuetracker.domain.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class IssueService {

    private final IssueRepository issueRepository;
    private final MemberRepository memberRepository;

    @Transactional
    public IssueDetailResponse registerIssue(String title, String contents, String issuerId) {
        //TODO
        // s3에 파일을 보내고 url을 받는다

        Member member = memberRepository.findByMemberId(issuerId).orElseThrow(NoSuchElementException::new);
        Issue savedIssue = issueRepository.save(Issue.of(member, title, contents, null, null, null, null));

        return new IssueDetailResponse(MemberDto.from(member), IssueDetail.from(savedIssue));
    }

    // 상세 정보
    @Transactional(readOnly = true)
    public IssueDetailResponse findById(Long issueNumber) {
        Issue targetIssue = issueRepository.findById(issueNumber)
                .orElseThrow(() -> new NoSuchElementException("해당하는 이슈가 없습니다."));

        return new IssueDetailResponse(MemberDto.from(targetIssue.getIssuer()), IssueDetail.from(targetIssue));
    }

    @Transactional(readOnly = true)
    public Page<IssueSimpleResponse> findByCondition(Pageable pageable, Boolean openStatus) {
        Page<Issue> issues = issueRepository.findByCondition(pageable, IssueCondition.of(openStatus, null, null, null));
        return issues.map(IssueSimpleResponse::from);
    }
}
