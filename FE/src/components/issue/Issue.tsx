import React, { useEffect, useState } from 'react';
import styles from './Issue.module.scss';
import { Input } from '../../common/Input';

// 매개변수 getTime();
function elapsedText(fetchedTime: number, createdTime: number) {
  // 초 (밀리초)
  const seconds = 1;
  // 분
  const minute = seconds * 60;
  // 시
  const hour = minute * 60;
  // 일
  const day = hour * 24;

  let elapsedTime = Math.trunc((fetchedTime - createdTime) / 1000);

  let elapsedText = '';
  if (elapsedTime < seconds) {
    elapsedText = '방금 전';
  } else if (elapsedTime < minute) {
    elapsedText = elapsedTime + '초 전';
  } else if (elapsedTime < hour) {
    elapsedText = Math.trunc(elapsedTime / minute) + '분 전';
  } else if (elapsedTime < day) {
    elapsedText = Math.trunc(elapsedTime / hour) + '시간 전';
  } else if (elapsedTime < day * 15) {
    elapsedText = Math.trunc(elapsedTime / day) + '일 전';
  }
  return elapsedText;
}

type IssuePropType = {
  id: number;
  title: string;
  milestoneTitle: string;
  createdAt: number;
  fetchedAt: number;
  userId: string;
  userImg: string;
  checkboxHandler: (e: React.ChangeEvent<HTMLInputElement>) => void;
  checkedIssues: string[];
};

const Issue = ({
  id,
  title,
  milestoneTitle,
  createdAt,
  fetchedAt,
  userId,
  userImg,
  checkboxHandler,
  checkedIssues,
}: IssuePropType) => {
  const passedTime = elapsedText(fetchedAt, createdAt);
  const [isChecked, setIsChecked] = useState(false);

  useEffect(() => {
    if (checkedIssues.includes(String(id))) setIsChecked(true);
    else setIsChecked(false);
  }, [checkedIssues]);

  return (
    <div className={styles.issueWrapper}>
      <div className={styles.checkBoxWrapper}>
        <Input
          label={`issue${id}`}
          info={{
            id: `${id}`,
            type: 'checkbox',
            value: 'issueSelect',
            onChange: checkboxHandler,
            checked: isChecked,
          }}
        />
      </div>
      <div className={styles.issue__contentWrapper}>
        <div className={styles.textWrapper}>
          <div className={styles.titleWrapper}>
            <span className={styles.title}>{title}</span>
            <span>badge</span>
          </div>
          <div className={styles.info}>
            <span>#{id}</span>
            <span>
              이 이슈가 {passedTime}, {userId}님에 의해 작성되었습니다.
            </span>
            <span>{milestoneTitle}</span>
          </div>
        </div>
        <div className={styles.right}>
          <div>무언가</div>
          <div>무언가</div>
          <div>무언가</div>
          <div>
            <img className={styles.avatar} src={userImg} alt="userAvatarImg" />
          </div>
        </div>
      </div>
    </div>
  );
};

export default Issue;
