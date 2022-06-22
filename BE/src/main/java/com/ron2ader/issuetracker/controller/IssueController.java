package com.ron2ader.issuetracker.controller;

import com.ron2ader.issuetracker.auth.Login;
import com.ron2ader.issuetracker.controller.issuedto.IssueCreateRequest;
import com.ron2ader.issuetracker.controller.issuedto.IssueDetailResponse;
import com.ron2ader.issuetracker.controller.issuedto.IssueSimpleResponse;
import com.ron2ader.issuetracker.controller.memberdto.MemberDto;
import com.ron2ader.issuetracker.service.IssueService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class IssueController {

    private final IssueService issueService;

    @PostMapping("/issues")
    public ResponseEntity<IssueDetailResponse> register(@Login MemberDto memberDto, IssueCreateRequest issueCreateRequest) {

        IssueDetailResponse issueDetailResponse = issueService.registerIssue(issueCreateRequest.getTitle(), issueCreateRequest.getContents(), memberDto.getMemberId()); // 임시 아이디

        return ResponseEntity.ok(issueDetailResponse);
    }

    @GetMapping("/issues/{issueNumber}")
    public ResponseEntity<IssueDetailResponse> showIssue(@PathVariable Long issueNumber) {
        IssueDetailResponse issueDetailResponse = issueService.findById(issueNumber);

        return ResponseEntity.ok(issueDetailResponse);
    }

    @GetMapping("/issues")
    public ResponseEntity<Page<IssueSimpleResponse>> showIssuesByOpenStatus(Pageable pageable, Boolean openStatus) {

        Page<IssueSimpleResponse> issues = issueService.findByCondition(pageable, openStatus);

        return ResponseEntity.ok(issues);
    }
}
