package com.ron2ader.issuetracker.domain.issue;

import org.springframework.data.jpa.repository.JpaRepository;

public interface IssueRepository extends JpaRepository<Issue, Long>, IssueCustomRepository {

}
