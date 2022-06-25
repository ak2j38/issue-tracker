package com.ron2ader.issuetracker.controller.issuedto;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class IssueCreateRequest {

    private String title;
    private String contents;
    private List<Long> assigneeIds;
    private List<Long> labelIds;
    private Long milestoneId;

}
