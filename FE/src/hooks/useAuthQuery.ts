import { ParsedQs } from 'qs';
import { useQuery } from 'react-query';

type ParsedQueryType =
  | string
  | ParsedQs
  | string[]
  | ParsedQs[]
  | undefined
  | null;

type JwtToken = { jwt: string };
type ReadonlyJwtToken = Readonly<JwtToken>;

// id, 아바타, accesstoken, refreshtoken

// backend endpoint : http://3.35.150.211:8080/auth/github?code=${code}
// for test : http://localhost:3030/jwttoken
const fetchAuth = async (code: ParsedQueryType): Promise<ReadonlyJwtToken> => {
  const response = await fetch(`http://localhost:3030/jwttoken`);
  if (!response.ok) {
    throw new Error('response not ok');
  }

  return response.json();
};

export const useAuthQuery = (code: ParsedQueryType) =>
  useQuery(['auth', code], () => fetchAuth(code));
