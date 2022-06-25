package com.ron2ader.issuetracker.controller.milestonedto;

import java.time.LocalDate;
import java.util.List;

import lombok.Getter;

@Getter
public class MilestoneRequest {

    private String title;
    private String description;
    private LocalDate endDate;

}
