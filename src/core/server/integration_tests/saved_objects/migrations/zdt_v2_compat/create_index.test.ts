/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { join } from 'path';
import '../jest_matchers';
import { type TestElasticsearchUtils } from '@kbn/core-test-helpers-kbn-server';
import {
  clearLog,
  getKibanaMigratorTestKit,
  startElasticsearch,
} from '../kibana_migrator_test_kit';
import { parseLogFile } from '../test_utils';
import { getBaseMigratorParams, getFooType, getLegacyType } from '../fixtures/zdt_base.fixtures';

const logFilePath = join(__dirname, 'create_index.test.log');

describe('ZDT with v2 compat - running on a fresh cluster', () => {
  let esServer: TestElasticsearchUtils['es'];

  beforeAll(async () => {
    await clearLog(logFilePath);
    esServer = await startElasticsearch();
  });

  afterAll(async () => {
    await esServer?.stop();
  });

  it('create the index with the correct mappings and meta', async () => {
    const fooType = getFooType();
    const legacyType = getLegacyType();

    const { runMigrations, client } = await getKibanaMigratorTestKit({
      ...getBaseMigratorParams({ kibanaVersion: '8.8.0' }),
      logFilePath,
      types: [fooType, legacyType],
    });

    const result = await runMigrations();

    expect(result).toEqual([
      {
        destIndex: '.kibana',
        elapsedMs: expect.any(Number),
        status: 'patched',
      },
    ]);

    const indices = await client.indices.get({ index: '.kibana*' });

    expect(Object.keys(indices)).toEqual(['.kibana_1']);

    const index = indices['.kibana_1'];
    const aliases = Object.keys(index.aliases ?? {}).sort();
    const mappings = index.mappings ?? {};
    const mappingMeta = mappings._meta ?? {};

    expect(aliases).toEqual(['.kibana', '.kibana_8.8.0']);

    expect(mappings.properties).toEqual(
      expect.objectContaining({
        foo: fooType.mappings,
        legacy: legacyType.mappings,
      })
    );

    expect(mappingMeta).toEqual({
      docVersions: {
        foo: '10.2.0',
        legacy: '10.0.0',
      },
      mappingVersions: {
        foo: '10.2.0',
        legacy: '10.0.0',
      },
      migrationState: expect.objectContaining({
        convertingDocuments: false,
      }),
    });

    const records = await parseLogFile(logFilePath);

    expect(records).toContainLogEntries(
      [
        'INIT -> CREATE_TARGET_INDEX',
        'CREATE_TARGET_INDEX -> INDEX_STATE_UPDATE_DONE',
        'INDEX_STATE_UPDATE_DONE -> DONE',
        'Migration completed',
      ],
      { ordered: true }
    );
  });
});
