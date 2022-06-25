package com.ron2ader.issuetracker.controller.milestonedto;

import com.ron2ader.issuetracker.domain.milestone.Milestone;
import java.time.LocalDate;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

@Getter
@AllArgsConstructor
@ToString
public class MilestoneResponse {

    private Long id;
    private String title;
    private String description;
    private LocalDate endDate;
    private Long openIssueCount;
    private Long closedIssueCount;

    public static MilestoneResponse from(Milestone milestone) {
        return new MilestoneResponse(milestone.getId(), milestone.getTitle(), milestone.getDescription(),
                milestone.getEndDate(), milestone.countOpenIssue(), milestone.countClosedIssue());
    }

}
