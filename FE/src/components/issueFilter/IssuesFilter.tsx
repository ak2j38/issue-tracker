import React, { useEffect, useRef, useState } from 'react';
import styles from './IssuesFilter.module.scss';
import { useNavigate } from 'react-router-dom';
import { InputWithRef } from '../../common/Input';
import FilterPopup from './FilterPopup';
import useClose from '../../hooks/useClose';

const IssuesFilter = () => {
  const navigate = useNavigate();
  const onClickHandler = () => {
    navigate('/addIssue');
  };
  const searchRef = useRef<HTMLInputElement>(null);

  const { popupRef, isOpen, setIsOpen } = useClose();
  
  return (
    <>
      <nav className={styles.filterNav}>
        <div className={styles.filterWrapper} onClick={() => setIsOpen(true)}>
          <div
            className={styles.filter}
            onClick={(e) => {
              e.stopPropagation();
              // 이벤트 버블링때문에 안된거였음.
              setIsOpen(true);
            }}
          >
            필터
            {isOpen && <FilterPopup ref={popupRef} />}
          </div>
          <InputWithRef
            label="search"
            ref={searchRef}
            info={{
              id: 'id',
              name: 'idInput',
              type: 'text',
              placeholder: 'is:issue is:open',
              className: styles.search,
            }}
          ></InputWithRef>
        </div>
        <div className={styles.filterButtonsWrapper}>
          <div className={styles.buttons}>
            <button>레이블 (0) </button>
            <button>마일스톤 (0) </button>
          </div>
          <button className={styles.addIssueButton} onClick={onClickHandler}>
            이슈작성
          </button>
        </div>
      </nav>
    </>
  );
};

export default IssuesFilter;
