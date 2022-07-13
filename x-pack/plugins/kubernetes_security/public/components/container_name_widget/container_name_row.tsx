/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { ReactNode, useState } from 'react';
import { EuiFlexItem, EuiText } from '@elastic/eui';
import { useStyles } from './styles';

export interface ContainerNameRowDeps {
  name: string;
  index?: number;
  filterButtonIn?: ReactNode;
  filterButtonOut?: ReactNode;
}

export const ContainerNameRow = ({
  name,
  index,
  filterButtonIn,
  filterButtonOut,
}: ContainerNameRowDeps) => {
  const [hoveredFilter, setHoveredFilter] = useState<number | null>(null);

  const styles = useStyles();

  return (
    <EuiFlexItem
      onMouseEnter={() => setHoveredFilter(index!)}
      onMouseLeave={() => setHoveredFilter(null)}
      data-test-subj={'containerNameSessionRow'}
    >
      <EuiText size="xs" css={styles.dataInfo}>
        {name}
        {hoveredFilter === index && (
          <div css={styles.filters}>
            {filterButtonIn}
            {filterButtonOut}
          </div>
        )}
      </EuiText>
    </EuiFlexItem>
  );
};
