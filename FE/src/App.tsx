import React, { lazy } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from 'react-query';
import { Provider } from 'react-redux';
import { CookiesProvider } from 'react-cookie';
import { ReactQueryDevtools } from 'react-query/devtools';
import { AddIssue } from './pages/addIssue';
import IssueList from './pages/issueList/IssueList';

import store from './store/store';
import Callback from './pages/callback/Callback';
const queryClient = new QueryClient();

const App = () => {
  const IssuesList = lazy(() => import('./pages/issueList/IssueList'));
  return (
    <Provider store={store}>
      <QueryClientProvider client={queryClient}>
        <CookiesProvider>
          <Router>
            <Routes>
              <Route path="/">
                <Route index element={<AuthPage />} />
                <Route path="issues" element={<IssueList />} />
                <Route path="addIssue" element={<AddIssue />} />
                <Route path="callback" element={<Callback />} />
              </Route>
            </Routes>
          </Router>
        </CookiesProvider>
        <ReactQueryDevtools initialIsOpen={false} />
      </QueryClientProvider>
    </Provider>
  );
};

export default App;
