package com.ron2ader.issuetracker.domain.member;

import com.ron2ader.issuetracker.domain.common.BaseEntity;
import java.util.Objects;
import lombok.*;

import javax.persistence.*;

@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
@Table(name = "member")
public class Member extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String memberId;
    private String avatarUrl;

    public static Member of(String memberId, String avatarUrl) {
        return new Member(null, memberId, avatarUrl);
    }

    public Member updateNonNull(Member member) {
        if (isUpdatable(member)) {
            this.memberId = member.getMemberId();
            this.avatarUrl = member.getAvatarUrl();
        }

        return this;
    }

    private boolean isUpdatable(Member member) {
        if (member == null) {
            return false;
        }
        return !this.memberId.equals(member.getMemberId()) || !this.avatarUrl.equals(member.getAvatarUrl());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Member member = (Member) o;
        return Objects.equals(id, member.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
