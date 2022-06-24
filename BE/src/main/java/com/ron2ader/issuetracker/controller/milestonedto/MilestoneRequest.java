package com.ron2ader.issuetracker.controller.milestonedto;

import java.time.LocalDate;
import lombok.Getter;

@Getter
public class MilestoneRequest {

    private String title;
    private LocalDate endDate;
    private String description;

}
