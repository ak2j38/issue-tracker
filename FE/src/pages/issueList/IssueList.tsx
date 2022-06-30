import React from 'react';
import { Header } from '@components/header';
import { useSearchParams } from 'react-router-dom';
import Issues from '@components/issue/Issues';
import IssuesFilter from '@components/issueFilter/IssuesFilter';

const IssueList = () => {
  const [searchParams, setSearchParams] = useSearchParams();

  setSearchParams('test');
  console.log(searchParams);
  return (
    <>
      <Header />
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
        }}
      >
        <IssuesFilter />
        <Issues />
      </div>
    </>
  );
};

export default IssueList;
