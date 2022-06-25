package com.ron2ader.issuetracker.controller.issuedto;

import com.ron2ader.issuetracker.domain.issue.Issue;
import java.time.LocalDateTime;
import java.util.Objects;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

@AllArgsConstructor
@Getter
@ToString
public class IssueDetail {

    private Long id;
    private String title;
    private String contents;
    private Boolean openStatus;
    private LocalDateTime createdAt;

    public static IssueDetail from(Issue issue) {
        return new IssueDetail(issue.getId(), issue.getTitle(), issue.getContents(), issue.getOpenStatus(), issue.getCreatedAt());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        IssueDetail that = (IssueDetail) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
