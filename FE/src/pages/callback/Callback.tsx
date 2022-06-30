import React, { useEffect } from 'react';
import { QueryClient, useQuery } from 'react-query';
import { useLocation, useNavigate } from 'react-router-dom';
import qs from 'qs';
import LoginLoading from '../../components/loginCallback/LoginLoading';
import LoginError from '../../components/loginCallback/LoginError';
import { useAuthQuery } from '../../hooks/useAuthQuery';
import { useCookies } from 'react-cookie';
const Callback = () => {
  const navigate = useNavigate();
  const { search } = useLocation();
  const { code } = qs.parse(search, {
    ignoreQueryPrefix: true,
  });
  const { status, data: token } = useAuthQuery(code);

  const [cookies, setCookie, removeCookie] = useCookies();

  // useEffect(() => {
  //   if (cookies.token) {
  //     console.log(cookies.token);
  //   }
  // }, []);
  if (status === 'success') {
    if (!cookies.token) {
      setCookie('token', token);
    }
    navigate(`/issues?id=${'test'}`);
  }

  if (status === 'loading') {
    navigate('/issues');
    return <LoginLoading />;
  }

  if (status === 'error') {
    return <LoginError />;
  }

  return <></>;
};

export default Callback;
