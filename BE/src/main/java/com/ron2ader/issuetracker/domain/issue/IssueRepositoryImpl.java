package com.ron2ader.issuetracker.domain.issue;

import static com.ron2ader.issuetracker.domain.issue.QIssue.issue;
import static com.ron2ader.issuetracker.domain.issue.QIssueAssignee.issueAssignee;
import static com.ron2ader.issuetracker.domain.member.QMember.member;
import static com.ron2ader.issuetracker.domain.reply.QReply.reply;

import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import com.ron2ader.issuetracker.controller.issuedto.IssueCondition;
import com.ron2ader.issuetracker.domain.member.Member;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.support.PageableExecutionUtils;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class IssueRepositoryImpl implements IssueCustomRepository {

    private final JPAQueryFactory jpaQueryFactory;

    @Override
    public Optional<Issue> findIssueById(Long id) {
        return Optional.ofNullable(jpaQueryFactory
            .selectFrom(issue)
            .leftJoin(issue.issuer, member)
            .where(
                issuerIdEq(id)
            )
            .fetchOne());
    }

    @Override
    public Page<Issue> findByCondition(Pageable pageable, IssueCondition issueCondition) {
        List<Issue> issues = jpaQueryFactory
            .select(issue)
            .from(issue)
            .leftJoin(issue.assignees, issueAssignee)
            .leftJoin(issue.replies, reply)
            .where(
                openStatusEq(issueCondition.getOpenStatus()),
                issuerEq(issueCondition.getIssuer()),
                issueAssigneeEq(issueCondition.getAssignee()),
                replyMemberEq(issueCondition.getIssuer())
            )
            .offset(pageable.getOffset())
            .limit(pageable.getPageSize())
            .fetch();

        JPAQuery<Issue> countQuery = jpaQueryFactory
            .select(issue)
            .from(issue)
            .leftJoin(issue.assignees, issueAssignee)
            .leftJoin(issue.replies, reply)
            .where(
                openStatusEq(issueCondition.getOpenStatus()),
                issuerEq(issueCondition.getIssuer()),
                issueAssigneeEq(issueCondition.getAssignee()),
                replyMemberEq(issueCondition.getIssuer())
            );

        return PageableExecutionUtils.getPage(issues, pageable, () -> countQuery.fetch().size());
    }

    private BooleanExpression issuerIdEq(Long id) {
        return issue.issuer.id.eq(id);
    }

    private BooleanExpression openStatusEq(Boolean openStatus) {
        return issue.openStatus.eq(openStatus);
    }

    private BooleanExpression issuerEq(Member issueConditionIssuer) {
        if (issueConditionIssuer == null) {
            return null;
        }

        return issue.issuer.eq(issueConditionIssuer);
    }

    private BooleanExpression issueAssigneeEq(Member assignee) {
        if (assignee == null) {
            return null;
        }

        return issueAssignee.assignee.eq(assignee);
    }

    private BooleanExpression replyMemberEq(Member issueConditionIssuer) {
        if (issueConditionIssuer == null) {
            return null;
        }

        return reply.member.eq(issueConditionIssuer);
    }
}
