package com.ron2ader.issuetracker.service;

import com.ron2ader.issuetracker.auth.Login;
import com.ron2ader.issuetracker.controller.issuedto.IssueCondition;
import com.ron2ader.issuetracker.controller.issuedto.IssueDetail;
import com.ron2ader.issuetracker.controller.issuedto.IssueDetailResponse;
import com.ron2ader.issuetracker.controller.issuedto.IssueSimpleResponse;
import com.ron2ader.issuetracker.controller.memberdto.MemberDto;
import com.ron2ader.issuetracker.domain.issue.*;
import com.ron2ader.issuetracker.domain.label.Label;
import com.ron2ader.issuetracker.domain.label.LabelRepository;
import com.ron2ader.issuetracker.domain.member.Member;
import com.ron2ader.issuetracker.domain.member.MemberRepository;
import com.ron2ader.issuetracker.domain.milestone.Milestone;
import com.ron2ader.issuetracker.domain.milestone.MilestoneRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class IssueService {

    private final IssueRepository issueRepository;
    private final MemberRepository memberRepository;
    private final LabelRepository labelRepository;
    private final MilestoneRepository milestoneRepository;
    private final IssueLabelRepository issueLabelRepository;
    private final IssueAssigneeRepository issueAssigneeRepository;

    @Transactional
    public Long registerIssue(String issuerId, String title, String contents,
                                             List<Long> assigneeIds, List<Long> labelIds, Long milestoneId) {

        Member member = memberRepository.findByMemberId(issuerId).orElseThrow(NoSuchElementException::new);
        Milestone milestone = milestoneRepository.findById(milestoneId).orElseThrow(NoSuchElementException::new);
        Issue createdIssue = issueRepository.save(Issue.createIssue(member, title, contents, milestone));

        /*
        * 메서드 분리 필요 (findAllById로 찾을지, 스트림을 활용해서 찾을지)
        * 예외에 대해서 더 공부하기
        * */
        try {
            List<Label> labels = labelRepository.findAllById(labelIds);
            List<Member> assignees = memberRepository.findAllById(assigneeIds);

            List<IssueLabel> issueLabels = labels.stream()
                    .map(label -> IssueLabel.of(createdIssue, label))
                    .collect(Collectors.toList());
            issueLabelRepository.saveAll(issueLabels);

            List<IssueAssignee> issueAssignees = assignees.stream()
                    .map(assignee -> IssueAssignee.of(createdIssue, assignee))
                    .collect(Collectors.toList());
            issueAssigneeRepository.saveAll(issueAssignees);

        } catch (IllegalArgumentException exception) {
            throw new NoSuchElementException(exception.getMessage());
        }

        return createdIssue.getId();
    }

    // 상세 정보
    @Transactional(readOnly = true)
    public IssueDetailResponse findById(Long issueNumber) {
        Issue targetIssue = issueRepository.findById(issueNumber)
                .orElseThrow(() -> new NoSuchElementException("해당하는 이슈가 없습니다."));

        return new IssueDetailResponse(MemberDto.from(targetIssue.getIssuer()), IssueDetail.from(targetIssue));
    }

    @Transactional(readOnly = true)
    public Page<IssueSimpleResponse> findByOpenStatus(Pageable pageable, Boolean openStatus) {
        Page<Issue> issues = issueRepository.findByCondition(pageable, IssueCondition.ofForFindOpenStatus(openStatus));
        return issues.map(IssueSimpleResponse::from);
    }

    @Transactional(readOnly = true)
    public Long countByStatus(Boolean openStatus) {
        return issueRepository.countByOpenStatus(openStatus);
    }
}
