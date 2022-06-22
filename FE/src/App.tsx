import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from 'react-query';
import { Provider } from 'react-redux';
import { ReactQueryDevtools } from 'react-query/devtools';
import { AddIssue } from './pages/addIssue';
import IssueList from '@pages/issueList/IssueList';
import AuthPage from '@pages/auth/AuthPage';
import store from './store/store';
import Callback from '@pages/callback/Callback';
const queryClient = new QueryClient();

const App = () => {
  return (
    <Provider store={store}>
      <QueryClientProvider client={queryClient}>
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
        <ReactQueryDevtools initialIsOpen={false} />
      </QueryClientProvider>
    </Provider>
  );
};

export default App;
