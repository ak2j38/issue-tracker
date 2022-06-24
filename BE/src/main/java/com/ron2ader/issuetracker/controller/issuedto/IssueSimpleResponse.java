package com.ron2ader.issuetracker.controller.issuedto;

import com.ron2ader.issuetracker.controller.labeldto.LabelResponse;
import com.ron2ader.issuetracker.controller.memberdto.MemberDto;
import com.ron2ader.issuetracker.domain.issue.Issue;
import java.util.List;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.LocalDateTime;

@AllArgsConstructor
@Getter
public class IssueSimpleResponse {

    private MemberDto memberDto;
    private Long issueNumber;
    private String title;
    private LocalDateTime createdAt;
    private List<MemberDto> assignees;
    private List<LabelResponse> labels;
    private String milestoneTitle;

    public static IssueSimpleResponse from(Issue issue) {
        return new IssueSimpleResponse(MemberDto.from(issue.getIssuer()),
            issue.getId(),
            issue.getTitle(),
            issue.getCreatedAt(),
            issue.getAssignees().stream()
                .map(issueAssignee -> MemberDto.from(issueAssignee.getAssignee()))
                .collect(Collectors.toList()),
            issue.getLabels().stream()
                .map(issueLabel -> LabelResponse.from(issueLabel.getLabel()))
                .collect(Collectors.toList()),
            issue.getMilestone().getTitle());
    }
}
