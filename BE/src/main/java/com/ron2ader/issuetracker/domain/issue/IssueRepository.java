package com.ron2ader.issuetracker.domain.issue;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface IssueRepository extends JpaRepository<Issue, Long>, IssueCustomRepository {

    Long countByOpenStatus(Boolean openStatus);

    @Query("select i from Issue i " +
            "left join fetch i.assignees " +
            "left join fetch i.milestone " +
            "where i.id = :id")
    @Override
    Optional<Issue> findById(@Param("id") Long id);
}
