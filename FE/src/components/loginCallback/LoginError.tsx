import React from 'react';
import styles from './LoginCallback.module.scss';
import { useNavigate } from 'react-router-dom';

const AuthError = () => {
  const navigate = useNavigate();
  return (
    <div className={styles.container}>
      <div>어떠한 img</div>
      <div className={styles.text}>로그인에 실패했습니다.</div>
      <br />
      <button className={styles.button} onClick={() => navigate('/')}>
        로그인 페이지로 돌아가기
      </button>
    </div>
  );
};

export default AuthError;
