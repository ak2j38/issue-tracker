package com.ron2ader.issuetracker.domain.label;

import com.ron2ader.issuetracker.domain.issue.IssueLabel;
import java.util.ArrayList;
import java.util.List;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;

@Entity
public class Label {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String title;
    private String color;
    private String description;

    @OneToMany(mappedBy = "label")
    private List<IssueLabel> issueLabels = new ArrayList<>();
}
