import React from 'react';
import styles from './addIssueForm.module.scss';
import { AddIssueInputs } from './addIssueInputs';

const AddIssueForm = (): JSX.Element => {
  return (
    <form>
      <div className={styles.Box}>
        <div className={styles.userImg}>
          <img src={'assets/img/UserImage.png'} />
        </div>
        <div className={styles.inputBox}>
          <AddIssueInputs />
        </div>
        <div></div>
      </div>
      <div className={styles.buttonBox}>
        <button>
          <img src={'assets/img/Ximage.png'} />
          작성 취소
        </button>
        <button type="submit">완료</button>
      </div>
    </form>
  );
};

export default AddIssueForm;
