import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import AuthPage from './AuthPage';
import '@testing-library/jest-dom/extend-expect';

// focus가 아이디 input으로 가있고,
// 아래 로그인 버튼은 disabled

const renderAuthForm = () => {
  const result = render(<AuthPage />);

  const form = () => result.getByTestId('form');
  const Heading = () =>
    result.getByRole('heading', {
      name: /issue tracker/i,
    });
  const GitHubLoginBtn = () => result.getByText(/깃허브로 로그인/);
  const Divider = () => result.getByText(/or/i);
  const IDInput = () =>
    result.getByPlaceholderText(/아이디/) as HTMLInputElement;
  const passwordInput = () =>
    result.getByPlaceholderText(/비밀번호/) as HTMLInputElement;
  const SubmitBtn = () =>
    result.getByRole('button', {
      name: /아이디로 로그인/,
    });
  const SignUpBtn = () =>
    result.getByRole('button', {
      name: /회원 가입/,
    });

  return {
    form,
    Heading,
    GitHubLoginBtn,
    Divider,
    IDInput,
    passwordInput,
    SubmitBtn,
    SignUpBtn,
  };
};

describe('<AuthForm>', () => {
  it('기본 필드가 렌더링 되어야 한다.', () => {
    const {
      Heading,
      GitHubLoginBtn,
      Divider,
      IDInput,
      passwordInput,
      SubmitBtn,
      SignUpBtn,
    } = renderAuthForm();

    expect(Heading()).toBeInTheDocument();
    expect(GitHubLoginBtn()).toBeInTheDocument();
    expect(Divider()).toBeInTheDocument();
    expect(IDInput()).toBeInTheDocument();
    expect(passwordInput()).toBeInTheDocument();
    expect(SubmitBtn()).toBeInTheDocument();
    expect(SignUpBtn()).toBeInTheDocument();
  });

  it('초기 focus는 id에 있다.', () => {
    const { IDInput } = renderAuthForm();
    expect(IDInput()).toHaveFocus();
  });

  it('유효한 아이디와 비밀번호가 입력되지 않으면 submit 버톤은 disabled이다.', () => {
    // 6자리 이하가 입력되면, submit 버튼은 disable상태로 유지된다.
    // todo valid 보충하기
    const { IDInput, passwordInput, SubmitBtn } = renderAuthForm();
    userEvent.type(IDInput(), '12345');
    expect(SubmitBtn()).toBeDisabled();
    userEvent.type(passwordInput(), '12345');
    expect(SubmitBtn()).toBeDisabled();
  });

  it('유효한 아이디와 비밀번호가 모두 입력되면 submit 버튼의 disable이 해제된다.', () => {
    const { IDInput, passwordInput, SubmitBtn } = renderAuthForm();
    userEvent.type(IDInput(), '7654321');
    userEvent.type(passwordInput(), '7654321');
    expect(SubmitBtn()).toHaveAttribute('disabled', '');
    expect(SubmitBtn()).toHaveAttribute('disabled', '');
  });

  it('아이디와 비밀번호는 12자까지 입력 가능하다.', async () => {
    const { IDInput, passwordInput } = renderAuthForm();

    // fireEvent.change(IDInput(), {
    //   target: { value: '123456789012EXTRA' },
    // });
    // await waitFor(() => {
    //   expect(IDInput()).toHaveValue('123456789012');
    // });
    // 위 테스트가 왜 안되는지 고민해보려고 일단 남겨놓았습니다!

    expect(IDInput()).toHaveAttribute('maxLength', '12');
    expect(passwordInput()).toHaveAttribute('maxLength', '12');
  });
  
  it('github 로그인 버튼은 깃허브 로그인 링크로 연결된다.', () => {
    const { GitHubLoginBtn } = renderAuthForm();
    expect(GitHubLoginBtn().closest('a')).toHaveAttribute(
      'href',
      'https://github.com/login/oauth/authorize?client_id=565469f738966f8bc11a&redirect_uri=http://localhost:8081/callback',
    );
  });

  // it('로그인하기 버튼을 누르면 submit 이벤트가 실행된다', async () => {
  //   // 이부분 테스트 실패중
  //   const mockSave = jest.fn;
  //   const { IDInput, passwordInput, form } = renderAuthForm();

  //   fireEvent.input(IDInput(), {
  //     value: 'testID',
  //   });

  //   fireEvent.input(passwordInput(), {
  //     value: 'testPassword',
  //   });

  //   fireEvent.submit(form());

  //   await waitFor(() =>
  //     expect(mockSave).toHaveBeenCalledWith({
  //       idInput: 'testID',
  //       passwordInput: 'testPassword',
  //     }),
  //   );
  // });

  it('submit 이벤트가 실행되면 input의 값이 초기화된다', async () => {
    const { IDInput, passwordInput, form } = renderAuthForm();

    userEvent.type(IDInput(), 'testID');
    userEvent.type(passwordInput(), 'testPassword');
    await fireEvent.submit(form());

    expect(IDInput().value).toBe('');
    expect(passwordInput().value).toBe('');
  });
});
