package com.ron2ader.issuetracker.domain.milestone;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface MilestoneRepository extends JpaRepository<Milestone, Long> {

    @Query("select m from Milestone m left join fetch m.issues where m.id =:id")
    Optional<Milestone> findByIdFetchIssue(@Param("id") Long id);

}
