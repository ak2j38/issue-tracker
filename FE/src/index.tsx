import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import '../src/styles/reset.css';

// if (process.env.NODE_ENV === 'development') {
//   const { worker } = require('./mocks/browsers');
//   worker.start();
// }

const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement,
);
root.render(<App />);
