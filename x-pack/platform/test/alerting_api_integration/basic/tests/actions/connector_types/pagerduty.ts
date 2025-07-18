/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { FtrProviderContext } from '../../../../common/ftr_provider_context';

export default function pagerdutyTest({ getService }: FtrProviderContext) {
  const supertest = getService('supertest');

  describe('pagerduty connector', () => {
    it('should return 403 when creating a pagerduty connector', async () => {
      await supertest
        .post('/api/actions/connector')
        .set('kbn-xsrf', 'foo')
        .send({
          name: 'A pagerduty connector',
          connector_type_id: '.pagerduty',
          config: {
            apiUrl: 'http://localhost',
          },
          secrets: {
            routingKey: 'pager-duty-routing-key',
          },
        })
        .expect(403, {
          statusCode: 403,
          error: 'Forbidden',
          message:
            'Action type .pagerduty is disabled because your basic license does not support it. Please upgrade your license.',
        });
    });
  });
}
