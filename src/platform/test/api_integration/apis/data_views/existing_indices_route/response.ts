/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import {
  ELASTIC_HTTP_VERSION_HEADER,
  X_ELASTIC_INTERNAL_ORIGIN_REQUEST,
} from '@kbn/core-http-common';
import { INITIAL_REST_VERSION_INTERNAL } from '@kbn/data-views-plugin/server/constants';
import { EXISTING_INDICES_PATH } from '@kbn/data-views-plugin/common/constants';
import { FtrProviderContext } from '../../../ftr_provider_context';

export default function ({ getService }: FtrProviderContext) {
  const esArchiver = getService('esArchiver');
  const supertest = getService('supertest');

  describe('_existing_indices response', () => {
    before(() =>
      esArchiver.load(
        'src/platform/test/api_integration/fixtures/es_archiver/index_patterns/basic_index'
      )
    );
    after(() =>
      esArchiver.unload(
        'src/platform/test/api_integration/fixtures/es_archiver/index_patterns/basic_index'
      )
    );

    it('returns an array of existing indices', async () => {
      await supertest
        .get(EXISTING_INDICES_PATH)
        .set(ELASTIC_HTTP_VERSION_HEADER, INITIAL_REST_VERSION_INTERNAL)
        .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
        .query({
          indices: ['basic_index', 'bad_index'],
        })
        .expect(200, ['basic_index']);
    });

    it('returns an empty array when no indices exist', async () => {
      await supertest
        .get(EXISTING_INDICES_PATH)
        .set(ELASTIC_HTTP_VERSION_HEADER, INITIAL_REST_VERSION_INTERNAL)
        .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
        .query({
          indices: ['bad_index'],
        })
        .expect(200, []);
    });
  });
}
