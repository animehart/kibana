/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useMemo } from 'react';
import { CSSObject } from '@emotion/react';
import { useEuiTheme } from '../../hooks';

export const useStyles = () => {
  const { euiTheme } = useEuiTheme();

  const cached = useMemo(() => {
    const { size, font } = euiTheme;

    const container: CSSObject = {
      padding: size.base,
      border: euiTheme.border.thin,
      borderRadius: euiTheme.border.radius.medium,
      overflow: 'auto',
    };

    const dataInfo: CSSObject = {
      marginBottom: size.xs,
      display: 'flex',
      alignItems: 'center',
      height: size.l,
    };

    const filters: CSSObject = {
      marginLeft: size.s,
    };

    const countValue: CSSObject = {
      fontWeight: font.weight.semiBold,
    };

    return {
      container,
      dataInfo,
      filters,
      countValue,
    };
  }, [euiTheme]);

  return cached;
};
