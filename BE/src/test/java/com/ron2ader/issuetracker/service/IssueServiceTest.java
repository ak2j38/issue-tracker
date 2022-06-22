package com.ron2ader.issuetracker.service;

import com.ron2ader.issuetracker.controller.issuedto.IssueCreateRequest;
import com.ron2ader.issuetracker.controller.issuedto.IssueDetailResponse;
import com.ron2ader.issuetracker.controller.issuedto.IssueSimpleResponse;
import com.ron2ader.issuetracker.domain.member.MemberRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("local")
@Transactional
class IssueServiceTest {

    @Autowired
    private IssueService issueService;

    @Autowired
    private MemberRepository memberRepository;

    private List<IssueCreateRequest> issues;
    private IssueCreateRequest issueCreateRequest;

    @BeforeEach
    void setUp() {
        issueCreateRequest = new IssueCreateRequest("title", "contents", null);

        issues = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
             issues.add(new IssueCreateRequest("title" + i, "contents" + i, null));
        }
    }

    @Test
    void registerIssueTest() {
        IssueDetailResponse issueDetailResponse = issueService.registerIssue(issueCreateRequest.getTitle(), issueCreateRequest.getContents(), "ron2");

        assertThat(issueDetailResponse.getMemberDto().getMemberId()).isEqualTo("ron2");
        assertThat(issueDetailResponse.getMemberDto().getAvatarUrl()).isEqualTo("asdfasdf.com");
        assertThat(issueDetailResponse.getIssueDetail().getTitle()).isEqualTo("title");
    }

    @Test
    void findByIdTest() {
        IssueDetailResponse issueDetailResponse = issueService.registerIssue(issueCreateRequest.getTitle(), issueCreateRequest.getContents(), "ron2");
        IssueDetailResponse findIssue = issueService.findById(issueDetailResponse.getIssueDetail().getId());

        assertThat(findIssue).isEqualTo(issueDetailResponse);
    }

    @Test
    void findAllByOpenStatusPagingTest() {
        for (int i = 0; i < 10; i++) {
            issueService.registerIssue(issues.get(i).getTitle(), issues.get(i).getTitle(), "ron2");
        }

        Page<IssueSimpleResponse> allByOpenStatus = issueService.findByCondition(PageRequest.of(0, 5), true);

        assertThat(allByOpenStatus.getTotalElements()).isEqualTo(10);
        assertThat(allByOpenStatus.getSize()).isEqualTo(5);
    }
}
