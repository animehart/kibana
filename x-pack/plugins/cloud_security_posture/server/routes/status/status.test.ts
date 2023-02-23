/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { calculateCspStatusCode } from './status';

import { POSTURE_TYPE_CSPM } from '@kbn/cloud-security-posture-plugin/common/constants';

describe('calculateCspStatusCode test', () => {
  it('Verify status when there are no permission', async () => {
    const statusCode:string = calculateCspStatusCode(
      POSTURE_TYPE_CSPM,
      {
        findingsLatest: 'unprivileged',
        findings: 'unprivileged',
        score: 'unprivileged',
      },
      1,
      1,
      1,
      ['cspm']
    );

    expect(statusCode).toMatch('unprivileged')
  }),
  it('Verify status when there are no findings, no healthy agents and no installed policy templates', async () => {
    const statusCode = calculateCspStatusCode(
      POSTURE_TYPE_CSPM,
      {
        findingsLatest: 'empty',
        findings: 'empty',
        score: 'empty',
      },
      0,
      0,
      0,
       []
    );

    expect(statusCode).toMatch('not-installed')
  })
  it('Verify status when there are findings and installed policies but no healthy agents', async () => {
    const statusCode = calculateCspStatusCode(
      POSTURE_TYPE_CSPM,
      {
        findingsLatest: 'empty',
        findings: 'not-empty',
        score: 'not-empty',
      },
      1,
      0,
      10,
      ['cspm']
    );

    expect(statusCode).toMatch('indexed')
  })
  it('Verify status when there are findings ,installed policies and healthy agents', async () => {
    const statusCode = calculateCspStatusCode(
      POSTURE_TYPE_CSPM,
      {
        findingsLatest: 'not-empty',
        findings: 'not-empty',
        score: 'not-empty',
      },
      1,
      1,
      10,
      ['cspm']
    );

    expect(statusCode).toMatch('indexed')
  })
  it('Verify status when there are no findings ,installed policies and no healthy agents', async () => {
    const statusCode = calculateCspStatusCode(
      POSTURE_TYPE_CSPM,
      {
        findingsLatest: 'empty',
        findings: 'empty',
        score: 'empty',
      },
      1,
      0,
      10,
      ['cspm']
    );

    expect(statusCode).toMatch('not-deployed')
  })
});
