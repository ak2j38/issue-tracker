package com.ron2ader.issuetracker.domain.issue;

import com.ron2ader.issuetracker.domain.common.BaseEntity;
import com.ron2ader.issuetracker.domain.label.Label;
import com.ron2ader.issuetracker.domain.member.Member;
import com.ron2ader.issuetracker.domain.milestone.Milestone;
import com.ron2ader.issuetracker.domain.reply.Reply;
import java.util.ArrayList;
import java.util.List;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
public class Issue extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "issuer_id")
    private Member issuer;

    private String title;

    private String contents;

    private Boolean openStatus;

    @OneToMany(mappedBy = "issue", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<IssueAssignee> assignees = new ArrayList<>();

    @OneToMany(mappedBy = "issue", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<IssueLabel> labels = new ArrayList<>();

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "milestone_id")
    private Milestone milestone;

    @OneToMany(mappedBy = "issue", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Reply> replies = new ArrayList<>();

    private Issue(Member issuer, String title, String contents, Milestone milestone) {
        this.issuer = issuer;
        this.title = title;
        this.contents = contents;
        this.openStatus = true;
        this.milestone = milestone;
    }

    public static Issue of(Member member, String title, String contents, List<IssueAssignee> assignees,
        List<IssueLabel> labels, Milestone milestone, List<Reply> replies) {
        return new Issue(null, member, title, contents, true, assignees, labels, milestone, replies);
    }

    public static Issue createIssue(Member issuer, String title, String contents, Milestone milestone)  {
        return new Issue(issuer, title, contents, milestone);
    }

    public void addReply(Reply reply) {
        reply.setIssue(this);
        this.replies.add(reply);
    }

}
