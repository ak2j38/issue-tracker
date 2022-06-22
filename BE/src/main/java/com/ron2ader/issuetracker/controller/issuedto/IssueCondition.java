package com.ron2ader.issuetracker.controller.issuedto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor(staticName = "of")
@Getter
public class IssueCondition {

    private Boolean openStatus;
    private Boolean isWriteByMe;
    private Boolean isAssignedToMe;
    private Boolean isCommentByMe;

}
