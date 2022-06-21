// jest-dom adds custom jest matchers for asserting on DOM nodes.
// allows you to do things like:
// expect(element).toHaveTextContent(/react/i)
// learn more: https://github.com/testing-library/jest-dom
import '@testing-library/jest-dom';

// src/setupTests.js
import { server } from './mocks/server.js';
// Establish API mocking before all tests.

beforeAll(() => server.listen());
// 들어오는 모든 요청을 msw로 라우팅한다.
// Reset any request handlers that we may add during the tests,
// so they don't affect other tests.
afterEach(() => server.resetHandlers());
// 각 테스트가 끝나면, 핸들러를 reset한다.
// Clean up after the tests are finished.

afterAll(() => server.close());
// 테스트가 끝나면 서버를 닫는다.
