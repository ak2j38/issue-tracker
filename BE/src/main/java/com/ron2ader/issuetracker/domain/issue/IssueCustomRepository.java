package com.ron2ader.issuetracker.domain.issue;

import com.ron2ader.issuetracker.controller.issuedto.IssueCondition;
import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.query.Param;

public interface IssueCustomRepository {

    Optional<Issue> findIssueById(@Param("id") Long id);

    Page<Issue> findByCondition(Pageable pageable, IssueCondition issueCondition);

}
