package com.ron2ader.issuetracker.controller.labeldto;

import com.ron2ader.issuetracker.domain.label.Label;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
@ToString
public class LabelResponse {

    private String title;
    private String color;

    public static LabelResponse from(Label label) {
        return new LabelResponse(label.getTitle(), label.getColor());
    }
}
