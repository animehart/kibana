/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { X_ELASTIC_INTERNAL_ORIGIN_REQUEST } from '@kbn/core-http-common';
import { FtrProviderContext } from '../../../ftr_provider_context';

// node scripts/functional_tests --config test/api_integration/config.js --grep="Resolve index API"

export default function ({ getService }: FtrProviderContext) {
  const supertest = getService('supertest');

  describe('Resolve index API', function () {
    it('should return 200 for a search for indices with wildcard', () =>
      supertest
        .get(`/internal/index-pattern-management/resolve_index/test*`)
        .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
        .expect(200));

    it('should return 404 when no indices match', () =>
      supertest
        .get(`/internal/index-pattern-management/resolve_index/test`)
        .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
        .expect(404));

    it('should return 404 when cluster is not found', () =>
      supertest
        .get(
          `/internal/index-pattern-management/resolve_index/cluster1:filebeat-*,cluster2:filebeat-*`
        )
        .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
        .expect(404));
  });
}
