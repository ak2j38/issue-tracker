package com.ron2ader.issuetracker.domain.issue;

import com.ron2ader.issuetracker.controller.issuedto.IssueFilter;
import java.util.List;
import java.util.Optional;
import org.springframework.data.repository.query.Param;

public interface IssueCustomRepository {

    List<Issue> findByIssueFilter(IssueFilter issueFilter);

}
