import React from 'react';
import { useNavigate } from 'react-router-dom';
import styles from './GithubLoginBtn.module.scss';

const url1 = `https://github.com/login/oauth/authorize?client_id=a1bc16e4f3e6c7202a57&redirect_uri=http://localhost:8081/`;
// 내 github client ID
const url2 = `https://github.com/login/oauth/authorize?client_id=565469f738966f8bc11a&redirect_uri=http://localhost:8081/`;
// 백엔드 github client ID

const GithubLoginBtn = () => {
  const navigate = useNavigate();
  return (
    <div>
      <a className={styles.link} onClick={() => navigate('/issues')}>
        <div className={styles.github_button}>깃허브로 로그인</div>
      </a>
    </div>
  );
};

export default GithubLoginBtn;
