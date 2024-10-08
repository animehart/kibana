/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { AggTypesDependencies, getAggTypes } from '.';
import { mockGetFieldFormatsStart } from './test_helpers';

import { isBucketAggType } from './buckets/bucket_agg_type';
import { isMetricAggType } from './metrics/metric_agg_type';

describe('AggTypesComponent', () => {
  const aggTypes = getAggTypes();
  const { buckets, metrics } = aggTypes;
  const aggTypesDependencies: AggTypesDependencies = {
    calculateBounds: jest.fn(),
    getConfig: jest.fn(),
    getFieldFormatsStart: mockGetFieldFormatsStart,
  };

  describe('bucket aggs', () => {
    test('all extend BucketAggType', () => {
      buckets.forEach(({ fn }) => {
        expect(isBucketAggType(fn(aggTypesDependencies))).toBeTruthy();
      });
    });
  });

  describe('metric aggs', () => {
    test('all extend MetricAggType', () => {
      metrics.forEach(({ fn }) => {
        expect(isMetricAggType(fn(aggTypesDependencies))).toBeTruthy();
      });
    });
  });
});
