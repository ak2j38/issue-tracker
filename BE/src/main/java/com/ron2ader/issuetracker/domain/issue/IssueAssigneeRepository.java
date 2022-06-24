package com.ron2ader.issuetracker.domain.issue;

import org.springframework.data.jpa.repository.JpaRepository;

public interface IssueAssigneeRepository extends JpaRepository<IssueAssignee, Long> {
}
