import React, { useEffect, useRef } from 'react';
import { ParsedQs } from 'qs';
import styles from './AuthForm.module.scss';
import { Input, InputWithRef } from '../../UI/Input';
import GithubLoginBtn from './GithubLoginBtn';
import useInput from '../../hooks/useInput';

export type parsedQueryType =
  | string
  | ParsedQs
  | string[]
  | ParsedQs[]
  | undefined
  | null;

const AuthForm = () => {
  const idRef = useRef<HTMLInputElement>(null);
  const {
    value: enteredID,
    isValid: idIsValid,
    valueChangeHandler: IDChangedHandler,
    reset: resetID,
  } = useInput((value) => value.length > 5);

  const {
    value: enteredPassword,
    isValid: passWordIsValid,
    valueChangeHandler: passWordChangedHandler,
    reset: resetPassword,
  } = useInput((value) => value.length > 5);

  useEffect(() => {
    idRef.current && idRef.current.focus();
  }, []);
  
  const formIsValid = idIsValid && passWordIsValid;

  const submitHandler = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.target as HTMLFormElement;
    () => {
      console.log(form);
    };
    resetID();
    resetPassword();
  };

  return (
    <section className={styles.section}>
      <h1 className={styles.title}>Issue Tracker</h1>
      <div className={styles.wrapper}>
        <GithubLoginBtn />
        <div className={styles.divider}>or</div>
        <form
          data-testid="form"
          className={styles.form}
          onSubmit={submitHandler}
        >
          <InputWithRef
            ref={idRef}
            label="id"
            info={{
              id: 'id',
              name: 'idInput',
              type: 'text',
              placeholder: '아이디',
              value: enteredID,
              onChange: IDChangedHandler,
              maxLength: 12,
            }}
          />
          <Input
            label="password"
            info={{
              id: 'password',
              name: 'passwordInput',
              type: 'password',
              placeholder: '비밀번호',
              value: enteredPassword,
              onChange: passWordChangedHandler,
              maxLength: 12,
            }}
          />
          <button
            type="submit"
            className={styles.login_button}
            disabled={formIsValid ? false : true}
          >
            아이디로 로그인
          </button>
        </form>
      </div>
      <button className={styles.signUp_button}>회원 가입</button>
    </section>
  );
};

export default AuthForm;
