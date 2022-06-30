import { QueryClient, useQuery } from 'react-query';

type fetchedDataType = {
  content: Readonly<fetchedContentType[]>;
  // 여기에 추가 되는 타입들이 있을 것 같아서, 일단 이렇게 작성했습니다.
};

export type fetchedContentType = {
  memberDto: {
    memberId: string;
    avatarUrl: string;
  };
  issueNumber: number;
  title: string;
  milestoneTitle: string;
  createdAt: string;
};

const fetchIssues = async (token: Readonly<string>) => {
  const response = await fetch(`http://localhost:3030/issues`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  if (!response.ok) {
    throw new Error('response not ok');
  }

  return response.json();
};

const queryClient = new QueryClient();

export const preFetchIssues = async (token: Readonly<string>) =>
  await queryClient.prefetchQuery('issues', () => fetchIssues(token));

export const useIssueQuery = (token: Readonly<string>) =>
  useQuery(['issues', token], () => fetchIssues(token), {
    refetchOnWindowFocus: false,
    retry: false,
  });
