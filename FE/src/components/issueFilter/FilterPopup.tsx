import React from 'react';
import { Input } from '../../common/Input';
import styles from './FilterPopup.module.scss';

const FilterPopup = React.forwardRef<HTMLDivElement>((props, ref) => {
  return (
    <div className={styles.popupWrapper} ref={ref}>
      <header>이슈 필터</header>
      <div className={styles.filterCondition}>
        열린 이슈
        <Input
          label="열린 이슈"
          info={{
            id: 'openedIssue',
            name: 'idInput',
            type: 'checkbox',
          }}
        />
      </div>
      <div className={styles.filterCondition}>
        내가 작성한 이슈
        <Input
          label="내가 작성한 이슈"
          info={{
            id: 'writtenIssue',
            name: 'idInput',
            type: 'checkbox',
          }}
        />
      </div>
      <div className={styles.filterCondition}>
        나에게 할당된 이슈
        <Input
          label="나에게 할당된 이슈"
          info={{
            id: 'assignedIssue',
            name: 'idInput',
            type: 'checkbox',
          }}
        />
      </div>
      <div className={styles.filterCondition}>
        내가 댓글을 남긴 이슈
        <Input
          label="내가 댓글을 남긴 이슈"
          info={{
            id: 'commentedIssue',
            name: 'idInput',
            type: 'checkbox',
          }}
        />
      </div>
      <div className={styles.filterCondition}>
        닫힌 이슈
        <Input
          label="열린 이슈"
          info={{
            id: 'issueOpen',
            name: 'idInput',
            type: 'checkbox',
          }}
        />
      </div>
    </div>
  );
});

export default FilterPopup;
