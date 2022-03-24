/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useMemo } from 'react';
import { useEuiTheme } from '@elastic/eui';
import { CSSObject } from '@emotion/react';
import { euiLightVars as theme } from '@kbn/ui-theme';

interface StylesDeps {
  height: number | undefined;
}

export const useStyles = ({ height = 500 }: StylesDeps) => {
  const { euiTheme } = useEuiTheme();

  const cached = useMemo(() => {
    const { border, colors } = euiTheme;

    const thinBorder = `${border.width.thin} solid ${colors.lightShade}!important`;

    const processTree: CSSObject = {
      height: `${height}px`,
      position: 'relative',
    };

    const detailPanel: CSSObject = {
      height: `${height}px`,
      borderRightWidth: '0px',
      borderLeft: thinBorder,
      borderRight: thinBorder,
    };

    const resizeHandle: CSSObject = {
      zIndex: 2,
    };

    const searchBar: CSSObject = {
      position: 'relative',
      margin: `${euiTheme.size.m} ${euiTheme.size.xs} !important`,
    };

    const buttonsEyeDetail: CSSObject = {
      margin: `${euiTheme.size.m} ${euiTheme.size.xs} !important`,
    };

    const sessionViewerComponent: CSSObject = {
      border: euiTheme.border.thin,
      borderRadius: euiTheme.border.radius.medium,
    };

    const toolBar: CSSObject = {
      backgroundColor: `${theme.euiFormBackgroundDisabledColor} !important`,
    };

    return {
      processTree,
      detailPanel,
      resizeHandle,
      searchBar,
      buttonsEyeDetail,
      sessionViewerComponent,
      toolBar,
    };
  }, [height, euiTheme]);

  return cached;
};
