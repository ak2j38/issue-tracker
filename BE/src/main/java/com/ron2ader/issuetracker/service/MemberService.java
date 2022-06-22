package com.ron2ader.issuetracker.service;

import com.ron2ader.issuetracker.controller.memberdto.MemberDto;
import com.ron2ader.issuetracker.domain.member.Member;
import com.ron2ader.issuetracker.domain.member.MemberRepository;
import java.util.NoSuchElementException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;

    @Transactional(readOnly = true)
    public MemberDto findMember(String memberId) {
        return MemberDto.from(
            memberRepository.findByMemberId(memberId)
                    .orElseThrow(() -> new NoSuchElementException("해당하는 회원이 없습니다.")));
    }

    public Member upsert(Member member) {
        Member findMember = memberRepository.findByMemberId(member.getMemberId())
            .map(m -> m.updateNonNull(member))
            .orElse(member);

        return memberRepository.save(findMember);
    }
}
