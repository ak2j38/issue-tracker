package com.ron2ader.issuetracker.domain.issue;

import static com.ron2ader.issuetracker.domain.issue.QIssue.issue;
import static com.ron2ader.issuetracker.domain.issue.QIssueAssignee.issueAssignee;
import static com.ron2ader.issuetracker.domain.member.QMember.member;
import static com.ron2ader.issuetracker.domain.reply.QReply.reply;

import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import com.ron2ader.issuetracker.controller.issuedto.IssueCondition;
import com.ron2ader.issuetracker.domain.member.QMember;
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
                issuerEq(issue.issuer, issueCondition.getIsWriteByMe()),
                issueAssigneeEq(issue.issuer, issueCondition.getIsAssignedToMe()),
                replyMemberEq(issue.issuer, issueCondition.getIsCommentByMe())
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
                issuerEq(issue.issuer, issueCondition.getIsWriteByMe()),
                issueAssigneeEq(issue.issuer, issueCondition.getIsAssignedToMe()),
                replyMemberEq(issue.issuer, issueCondition.getIsCommentByMe())
            );

        return PageableExecutionUtils.getPage(issues, pageable, () -> countQuery.fetch().size());
    }

    private BooleanExpression issuerIdEq(Long id) {
        return issue.issuer.id.eq(id);
    }

    private BooleanExpression openStatusEq(Boolean openStatus) {
        return issue.openStatus.eq(openStatus);
    }

    private BooleanExpression issuerEq(QMember issuer, Boolean isWriteByMe) {
        if (isWriteByMe == null) {
            return null;
        }

        return issue.issuer.eq(issuer);
    }

    private BooleanExpression issueAssigneeEq(QMember issuer, Boolean isAssignedToMe) {
        if (isAssignedToMe == null) {
            return null;
        }

        return issueAssignee.assignee.eq(issuer);
    }

    private BooleanExpression replyMemberEq(QMember issuer, Boolean isCommentByMe) {
        if (isCommentByMe == null) {
            return null;
        }

        return reply.member.eq(issuer);
    }
}
