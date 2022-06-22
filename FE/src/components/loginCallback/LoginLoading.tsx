import React from 'react';
import styles from './LoginCallback.module.scss';

const LoginLoading = () => {
  return (
    <div className={styles.container}>
      <div className={styles.loader} />
      <br />
      <div className={styles.text}>로그인 진행중</div>
    </div>
  );
};
export default LoginLoading;
