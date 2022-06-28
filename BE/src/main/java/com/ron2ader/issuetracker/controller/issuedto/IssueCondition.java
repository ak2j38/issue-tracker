package com.ron2ader.issuetracker.controller.issuedto;

import com.ron2ader.issuetracker.domain.label.Label;
import com.ron2ader.issuetracker.domain.member.Member;
import com.ron2ader.issuetracker.domain.milestone.Milestone;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor(staticName = "of")
@Getter
public class IssueCondition {

    private Boolean openStatus;
    private Member assignee;
    private Label label;
    private Milestone milestone;
    private Member issuer;

}