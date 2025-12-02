import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './app';

// We are assuming a build environment (like Vercel deploying a Create React App)
// will handle the CSS, so no explicit CSS import is needed here.

const container = document.getElementById('root');
const root = createRoot(container);

root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
