package com.ron2ader.issuetracker.domain.issue;

import org.springframework.data.jpa.repository.JpaRepository;

public interface IssueLabelRepository extends JpaRepository<IssueLabel, Long> {
}
