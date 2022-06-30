import React from 'react';
import AddIssueForm from '../../components/addIssue/addIssueForm';
import styles from './addIssue.module.scss';
import Header from '../../components/header/header';
export const AddIssue = (): JSX.Element => {
  return (
    <>
      <Header />
      <div className={`${styles.Box} ${styles.titleBox}`}>
        <h2 className={styles.title}>새로운 이슈 작성</h2>
      </div>
      <div className={`${styles.Box} ${styles.formBox}`}>
        <AddIssueForm />
      </div>
    </>
  );
};
