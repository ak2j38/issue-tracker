import React, { useEffect } from 'react';
import { useQuery } from 'react-query';
import { useLocation, useNavigate } from 'react-router-dom';
import qs from 'qs';
import LoginLoading from '@components/loginCallback/LoginLoading';
import LoginError from '@components/loginCallback/LoginError';

// // backend url : http://3.34.47.60:8080/auth/github?code=${code}
// // test url : https://test-234b2-default-rtdb.firebaseio.com/.json

// 리액트 쿼리 오류핸들링이 계속 안먹히던 이유가,
// suspense 사용을 모두 true로 해놨기 때문이라는거 . . . .

const authFetcher = async () => {
  const response = await fetch(
    `https://test-234b2-default-rtdb.firebaseio.com/.json`,
  );
  if (!response.ok) {
    throw new Error('response not ok');
  }

  return response.json();
};

const Callback = () => {
  const navigate = useNavigate();
  const { search } = useLocation();
  const { code } = qs.parse(search, {
    ignoreQueryPrefix: true,
  });
  // 원래는 이 code를 통해서 로그인 요청을 보내는 거지만,
  // 임시 url로 페치요청
  const { status, data } = useQuery('auth', authFetcher, {
    refetchOnWindowFocus: false,
    retry: false,
  });

  if (status === 'loading') {
    return <LoginLoading />;
  }
  if (status === 'error') {
    return <LoginError />;
  }

  if (status === 'success') {
    navigate('/issues');
  }

  return <></>;
};

export default Callback;
