/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Decorator, StoryContext } from '@storybook/react';
import type { FC, PropsWithChildren } from 'react';
import React, { useEffect, useMemo, useState } from 'react';
import { BehaviorSubject } from 'rxjs';
import type { CoreTheme } from '@kbn/core/public';
import { EuiThemeProvider } from '@kbn/kibana-react-plugin/common';
import { KibanaThemeProvider } from '@kbn/react-kibana-context-theme';

export const useGlobalStorybookTheme = ({ globals: { euiTheme } }: StoryContext) => {
  const theme = useMemo(() => euiThemeFromId(euiTheme), [euiTheme]);
  const [theme$] = useState(() => new BehaviorSubject(theme));

  useEffect(() => {
    theme$.next(theme);
  }, [theme$, theme]);

  return {
    theme,
    theme$,
  };
};

export const GlobalStorybookThemeProviders: FC<
  PropsWithChildren<{
    storyContext: StoryContext;
  }>
> = ({ children, storyContext }) => {
  const { theme, theme$ } = useGlobalStorybookTheme(storyContext);
  return (
    <KibanaThemeProvider theme={{ theme$ }}>
      <EuiThemeProvider darkMode={theme.darkMode}>{children}</EuiThemeProvider>
    </KibanaThemeProvider>
  );
};

export const decorateWithGlobalStorybookThemeProviders: Decorator = (
  wrappedStory,
  storyContext
) => (
  <GlobalStorybookThemeProviders storyContext={storyContext}>
    {wrappedStory()}
  </GlobalStorybookThemeProviders>
);

const euiThemeFromId = (themeId: string): CoreTheme => {
  switch (themeId) {
    case 'v8.dark':
      return { darkMode: true, name: 'amsterdam' };
    default:
      return { darkMode: false, name: 'amsterdam' };
  }
};
