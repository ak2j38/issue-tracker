package com.ron2ader.issuetracker.service;

import com.ron2ader.issuetracker.controller.issuedto.IssueDetailResponse;
import com.ron2ader.issuetracker.domain.member.MemberRepository;
import com.ron2ader.issuetracker.domain.milestone.MilestoneRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.jdbc.Sql;

import java.util.List;

@SpringBootTest
@ActiveProfiles("local")
@Sql("classpath:sql/data.sql")
class IssueServiceTest {

    private final IssueService issueService;
    private final MemberRepository memberRepository;
    private final MilestoneRepository milestoneRepository;


    @Autowired
    public IssueServiceTest(IssueService issueService,
                            MemberRepository memberRepository,
                            MilestoneRepository milestoneRepository) {
        this.issueService = issueService;
        this.memberRepository = memberRepository;
        this.milestoneRepository = milestoneRepository;
    }

    @BeforeEach
    void setUp() {

    }

    @Test
    @DisplayName("issue를 등록하면 등록된 이슈의 아이디를 반환한다.")
    void registerIssueTest() {
        Long createdIssueId = issueService.registerIssue("ron2",
                "first issue",
                "issue contents",
                List.of(1L, 2L),
                List.of(1L, 2L),
                1L);

        IssueDetailResponse issueDetailResponse = issueService.findById(createdIssueId);
        System.out.println(issueDetailResponse.toString());


    }

//
//    @Test
//    void findByIdTest() {
//        IssueDetailResponse issueDetailResponse = issueService.registerIssue(issueCreateRequest.getTitle(), issueCreateRequest.getContents(), "ron2");
//        IssueDetailResponse findIssue = issueService.findById(issueDetailResponse.getIssueDetail().getId());
//
//        assertThat(findIssue).isEqualTo(issueDetailResponse);
//    }
//
//    @Test
//    void findAllByOpenStatusPagingTest() {
//        for (int i = 0; i < 10; i++) {
//            issueService.registerIssue(issues.get(i).getTitle(), issues.get(i).getTitle(), "ron2");
//        }
//
//        Page<IssueSimpleResponse> allByOpenStatus = issueService.findByOpenStatus(PageRequest.of(0, 5), true);
//
//        assertThat(allByOpenStatus.getTotalElements()).isEqualTo(10);
//        assertThat(allByOpenStatus.getSize()).isEqualTo(5);
//    }
}
