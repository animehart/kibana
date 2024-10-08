/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { Vis } from '@kbn/visualizations-plugin/public';
import { sampleHeatmapVis } from './sample_vis.test.mocks';
import { buildExpression } from '@kbn/expressions-plugin/public';

import { toExpressionAst } from './to_ast';
import { HeatmapVisParams } from './types';

jest.mock('@kbn/expressions-plugin/public', () => ({
  ...(jest.requireActual('@kbn/expressions-plugin/public') as any),
  buildExpression: jest.fn().mockImplementation(() => ({
    toAst: () => ({
      type: 'expression',
      chain: [],
    }),
  })),
}));

describe('heatmap vis toExpressionAst function', () => {
  let vis: Vis<HeatmapVisParams>;

  const params = {
    timefilter: {},
    timeRange: {},
    abortSignal: {},
  } as any;

  beforeEach(() => {
    vis = sampleHeatmapVis as any;
  });

  it('should match basic snapshot', () => {
    toExpressionAst(vis, params);
    const [builtExpression] = (buildExpression as jest.Mock).mock.calls.pop()[0];

    expect(builtExpression).toMatchSnapshot();
  });
});
