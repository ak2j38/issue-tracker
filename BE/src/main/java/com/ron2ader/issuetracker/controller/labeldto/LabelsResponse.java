package com.ron2ader.issuetracker.controller.labeldto;

import com.ron2ader.issuetracker.domain.label.Label;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class LabelsResponse {

    private Long id;
    private String title;
    private String color;

    public static LabelsResponse from(Label label) {
        return new LabelsResponse(label.getId(), label.getTitle(), label.getColor());
    }
}
