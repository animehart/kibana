/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { elasticsearchClientMock } from '@kbn/core-elasticsearch-client-server-mocks';
import { loggingSystemMock } from '@kbn/core/server/mocks';
import { createBenchmarkScoreIndex } from './create_indices';
import {
  BENCHMARK_SCORE_INDEX_DEFAULT_NS,
  BENCHMARK_SCORE_INDEX_PATTERN,
  BENCHMARK_SCORE_INDEX_TEMPLATE_NAME,
  CSP_INGEST_TIMESTAMP_PIPELINE,
} from '../../common/constants';
import type { IndicesGetIndexTemplateIndexTemplateItem } from '@elastic/elasticsearch/lib/api/types';

const mockEsClient = elasticsearchClientMock.createClusterClient().asScoped().asInternalUser;

describe('createBenchmarkScoreIndex', () => {
  let logger: ReturnType<typeof loggingSystemMock.createLogger>;

  beforeEach(() => {
    logger = loggingSystemMock.createLogger();
    jest.resetAllMocks();

    // Mock the new template verification functions
    mockEsClient.indices.getIndexTemplate.mockResolvedValue({
      index_templates: [{ name: 'test-template' } as IndicesGetIndexTemplateIndexTemplateItem],
    });

    // Mock mapping verification
    mockEsClient.indices.getMapping.mockResolvedValue({
      [BENCHMARK_SCORE_INDEX_DEFAULT_NS]: {
        mappings: {
          properties: {
            namespace: { type: 'keyword' },
            '@timestamp': { type: 'date' },
            cluster_id: { type: 'keyword' },
            'resource.id': { type: 'keyword' },
          },
        },
      },
    });

    // Mock index existence check
    mockEsClient.indices.exists.mockResolvedValue(false);
  });

  it('should delete old index template from prev verions first', async () => {
    mockEsClient.indices.getIndexTemplate.mockResolvedValueOnce({
      index_templates: [{ name: 'foo' } as IndicesGetIndexTemplateIndexTemplateItem],
    });
    // @ts-ignore
    await createBenchmarkScoreIndex(mockEsClient, { serverless: { enabled: false } }, logger);
    expect(mockEsClient.indices.deleteIndexTemplate).toHaveBeenCalledTimes(1);
    expect(mockEsClient.indices.deleteIndexTemplate).toHaveBeenCalledWith({
      name: 'cloud_security_posture.scores',
    });
  });

  it('should create index template with the correct index pattern, index name and default ingest pipeline', async () => {
    // @ts-ignore
    await createBenchmarkScoreIndex(mockEsClient, { serverless: { enabled: false } }, logger);
    expect(mockEsClient.indices.putIndexTemplate).toHaveBeenCalledTimes(1);
    expect(mockEsClient.indices.putIndexTemplate).toHaveBeenCalledWith(
      expect.objectContaining({
        name: BENCHMARK_SCORE_INDEX_TEMPLATE_NAME,
        index_patterns: BENCHMARK_SCORE_INDEX_PATTERN,
        template: expect.objectContaining({
          settings: {
            index: {
              default_pipeline: CSP_INGEST_TIMESTAMP_PIPELINE,
            },
            lifecycle: {
              name: '',
            },
          },
        }),
      })
    );
  });

  it('should create index template the correct index patter, index name and default ingest pipeline but without lifecycle in serverless', async () => {
    await createBenchmarkScoreIndex(
      mockEsClient,
      { serverless: { enabled: true }, enabled: true, enableExperimental: [] },
      logger
    );
    expect(mockEsClient.indices.putIndexTemplate).toHaveBeenCalledTimes(1);
    expect(mockEsClient.indices.putIndexTemplate).toHaveBeenCalledWith(
      expect.objectContaining({
        name: BENCHMARK_SCORE_INDEX_TEMPLATE_NAME,
        index_patterns: BENCHMARK_SCORE_INDEX_PATTERN,
        template: expect.objectContaining({
          settings: expect.not.objectContaining({
            lifecycle: {
              name: '',
            },
          }),
        }),
      })
    );
  });

  it('should create index if does not exist', async () => {
    mockEsClient.indices.exists.mockResolvedValueOnce(false);

    await createBenchmarkScoreIndex(
      mockEsClient,
      { serverless: { enabled: true }, enabled: true, enableExperimental: [] },
      logger
    );

    // Should wait for template to be available
    expect(mockEsClient.indices.getIndexTemplate).toHaveBeenCalledWith({
      name: BENCHMARK_SCORE_INDEX_TEMPLATE_NAME,
    });

    expect(mockEsClient.indices.create).toHaveBeenCalledTimes(1);
    expect(mockEsClient.indices.create).toHaveBeenCalledWith({
      index: BENCHMARK_SCORE_INDEX_DEFAULT_NS,
    });
    expect(mockEsClient.indices.putMapping).toHaveBeenCalledTimes(0);

    // Should perform final verification
    expect(mockEsClient.indices.getMapping).toHaveBeenCalledWith({
      index: BENCHMARK_SCORE_INDEX_DEFAULT_NS,
    });
  });

  it('should update index mapping if index exists and mapping is compatible', async () => {
    mockEsClient.indices.exists.mockResolvedValueOnce(true);

    await createBenchmarkScoreIndex(
      mockEsClient,
      { serverless: { enabled: true }, enabled: true, enableExperimental: [] },
      logger
    );

    // Should wait for template to be available
    expect(mockEsClient.indices.getIndexTemplate).toHaveBeenCalledWith({
      name: BENCHMARK_SCORE_INDEX_TEMPLATE_NAME,
    });

    // Should check mapping compatibility
    expect(mockEsClient.indices.getMapping).toHaveBeenCalledWith({
      index: BENCHMARK_SCORE_INDEX_DEFAULT_NS,
    });

    expect(mockEsClient.indices.create).toHaveBeenCalledTimes(0);
    expect(mockEsClient.indices.putMapping).toHaveBeenCalledTimes(1);
  });

  it('should recreate index if mapping is incompatible', async () => {
    mockEsClient.indices.exists.mockResolvedValueOnce(true);

    // Mock incompatible mapping - namespace as text instead of keyword
    mockEsClient.indices.getMapping.mockResolvedValueOnce({
      [BENCHMARK_SCORE_INDEX_DEFAULT_NS]: {
        mappings: {
          properties: {
            namespace: { type: 'text' }, // Wrong type!
            '@timestamp': { type: 'date' },
          },
        },
      },
    });

    await createBenchmarkScoreIndex(
      mockEsClient,
      { serverless: { enabled: true }, enabled: true, enableExperimental: [] },
      logger
    );

    // Should delete and recreate the index
    expect(mockEsClient.indices.delete).toHaveBeenCalledWith({
      index: BENCHMARK_SCORE_INDEX_DEFAULT_NS,
    });
    expect(mockEsClient.indices.create).toHaveBeenCalledWith({
      index: BENCHMARK_SCORE_INDEX_DEFAULT_NS,
    });
  });

  it('should throw error if final mapping verification fails', async () => {
    mockEsClient.indices.exists.mockResolvedValueOnce(false);

    // Mock final verification failure
    mockEsClient.indices.getMapping
      .mockResolvedValueOnce({
        [BENCHMARK_SCORE_INDEX_DEFAULT_NS]: {
          mappings: {
            properties: {
              namespace: { type: 'keyword' },
            },
          },
        },
      })
      .mockResolvedValueOnce({
        [BENCHMARK_SCORE_INDEX_DEFAULT_NS]: {
          mappings: {
            properties: {
              namespace: { type: 'text' }, // Wrong type in final verification
            },
          },
        },
      });

    await expect(
      createBenchmarkScoreIndex(
        mockEsClient,
        { serverless: { enabled: true }, enabled: true, enableExperimental: [] },
        logger
      )
    ).rejects.toThrow('Index mapping verification failed');
  });
});
