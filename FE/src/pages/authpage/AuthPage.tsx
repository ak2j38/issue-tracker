import React from 'react';
import AuthForm from '../../components/authFrom/AuthForm';
import styles from './AuthPage.module.scss';

const AuthPage = () => {
  return (
    <div className={styles.container}>
      <AuthForm />
    </div>
  );
};

export default AuthPage;