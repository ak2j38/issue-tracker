package com.ron2ader.issuetracker.controller.milestonedto;

import com.ron2ader.issuetracker.domain.milestone.Milestone;
import java.time.LocalDate;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(staticName = "of")
public class MilestoneResponse {

    private Long id;
    private String title;
    private String description;
    private LocalDate endDate;
    private Long openIssueCount;
    private Long closeIssueCount;

    public static MilestoneResponse fromForRegister(Milestone milestone) {
        return new MilestoneResponse(milestone.getId(), milestone.getTitle(), milestone.getDescription(), milestone.getEndDate(), 0L, 0L);
    }
}
