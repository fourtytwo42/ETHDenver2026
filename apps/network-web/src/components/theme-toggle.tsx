'use client';

import { useEffect, useState } from 'react';

type Theme = 'dark' | 'light';

const STORAGE_KEY = 'xclaw_theme';

function setTheme(theme: Theme) {
  document.documentElement.setAttribute('data-theme', theme);
}

export function ThemeToggle() {
  const [theme, setThemeState] = useState<Theme>('dark');

  useEffect(() => {
    const persisted = window.localStorage.getItem(STORAGE_KEY);
    if (persisted === 'light' || persisted === 'dark') {
      setThemeState(persisted);
      setTheme(persisted);
      return;
    }

    setTheme('dark');
  }, []);

  return (
    <button
      type="button"
      className="theme-toggle"
      onClick={() => {
        const next = theme === 'dark' ? 'light' : 'dark';
        setThemeState(next);
        setTheme(next);
        window.localStorage.setItem(STORAGE_KEY, next);
      }}
      aria-label="Toggle dark and light theme"
    >
      {theme === 'dark' ? 'Light' : 'Dark'} mode
    </button>
  );
}
