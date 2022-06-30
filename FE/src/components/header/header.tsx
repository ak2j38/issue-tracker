import React from 'react';
import styles from './header.module.scss';

const Header = (): JSX.Element => {
  return (
    <header>
      <div className={styles.box}>
        <h1>
          <img src={'assets/img/LogotypeMedium.png'} />
        </h1>
        <img src={'assets/img/UserImage.png'} />
      </div>
    </header>
  );
};

export default Header;
