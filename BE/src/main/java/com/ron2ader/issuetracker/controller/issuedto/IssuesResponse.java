package com.ron2ader.issuetracker.controller.issuedto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;

@RequiredArgsConstructor
@Getter
public class IssuesResponse {

    private final Long openCount;
    private final Long closeCount;
    private final Page<IssueSimpleResponse> issueSimpleResponse;

}
