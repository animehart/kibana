/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
import { errors } from '@elastic/elasticsearch';
import type { MappingTypeMapping } from '@elastic/elasticsearch/lib/api/types';
import type { ElasticsearchClient, Logger } from '@kbn/core/server';
import { STACK_COMPONENT_TEMPLATE_LOGS_SETTINGS } from '@kbn/fleet-plugin/server/constants';
import {
  BENCHMARK_SCORE_INDEX_DEFAULT_NS,
  BENCHMARK_SCORE_INDEX_PATTERN,
  BENCHMARK_SCORE_INDEX_TEMPLATE_NAME,
  CLOUD_SECURITY_POSTURE_PACKAGE_NAME,
} from '../../common/constants';
import { createPipelineIfNotExists } from './create_processor';
import { benchmarkScoreMapping } from './benchmark_score_mapping';
import { latestFindingsPipelineIngestConfig, scorePipelineIngestConfig } from './ingest_pipelines';
import { latestIndexConfigs } from './latest_indices';
import type { IndexConfig, IndexTemplateParams } from './types';

import type { CloudSecurityPostureConfig } from '../config';

interface IndexTemplateSettings {
  index: {
    default_pipeline: string;
    codec?: string;
    mapping?: {
      ignore_malformed: boolean;
    };
  };
  lifecycle?: { name: string };
}

// TODO: Add integration tests
export const initializeCspIndices = async (
  esClient: ElasticsearchClient,
  cloudSecurityPostureConfig: CloudSecurityPostureConfig,
  latestFindingsIndexAutoCreated: boolean,
  logger: Logger
) => {
  await Promise.allSettled([
    createPipelineIfNotExists(esClient, scorePipelineIngestConfig, logger),
    createPipelineIfNotExists(esClient, latestFindingsPipelineIngestConfig, logger),
  ]);
  const [createVulnerabilitiesLatestIndexPromise, createBenchmarkScoreIndexPromise] =
    await Promise.allSettled([
      createLatestIndex(
        esClient,
        latestIndexConfigs.vulnerabilities,
        cloudSecurityPostureConfig,
        logger
      ),
      createBenchmarkScoreIndex(esClient, cloudSecurityPostureConfig, logger),
    ]);

  if (createVulnerabilitiesLatestIndexPromise.status === 'rejected') {
    logger.error(createVulnerabilitiesLatestIndexPromise.reason);
  }
  if (createBenchmarkScoreIndexPromise.status === 'rejected') {
    logger.error(createBenchmarkScoreIndexPromise.reason);
  }

  if (!latestFindingsIndexAutoCreated) {
    try {
      await createLatestIndex(
        esClient,
        latestIndexConfigs.findings,
        cloudSecurityPostureConfig,
        logger
      );
    } catch (e) {
      logger.error(`Failed to create latest findings index: ${e}`);
    }
  }
};

export const createBenchmarkScoreIndex = async (
  esClient: ElasticsearchClient,
  cloudSecurityPostureConfig: CloudSecurityPostureConfig,
  logger: Logger
) => {
  try {
    // Deletes old assets from previous versions as part of upgrade process
    const INDEX_TEMPLATE_V830 = 'cloud_security_posture.scores';
    await deleteIndexTemplateSafe(esClient, logger, INDEX_TEMPLATE_V830);

    const settings: IndexTemplateSettings = {
      index: {
        default_pipeline: scorePipelineIngestConfig.id,
      },
      lifecycle: { name: '' },
    };
    if (cloudSecurityPostureConfig.serverless.enabled) delete settings.lifecycle;

    // We always want to keep the index template updated
    logger.info(
      `[TEMPLATE_UPDATE] Updating index template with benchmark score mapping [Name: ${BENCHMARK_SCORE_INDEX_TEMPLATE_NAME}]`
    );

    // Log the mapping we're about to apply
    logger.info(
      `[TEMPLATE_UPDATE] Namespace field in mapping: ${JSON.stringify(
        benchmarkScoreMapping.properties?.namespace
      )}`
    );

    await esClient.indices.putIndexTemplate({
      name: BENCHMARK_SCORE_INDEX_TEMPLATE_NAME,
      index_patterns: BENCHMARK_SCORE_INDEX_PATTERN,
      template: {
        mappings: benchmarkScoreMapping,
        settings,
      },
      _meta: {
        package: {
          name: CLOUD_SECURITY_POSTURE_PACKAGE_NAME,
        },
        managed_by: 'cloud_security_posture',
        managed: true,
      },
      priority: 500,
    });

    logger.info(
      `[TEMPLATE_UPDATE] Successfully updated index template [Name: ${BENCHMARK_SCORE_INDEX_TEMPLATE_NAME}]`
    );

    // Wait for template to be available before proceeding
    await waitForIndexTemplate(esClient, BENCHMARK_SCORE_INDEX_TEMPLATE_NAME, logger);

    // Check if index exists and verify its mapping compatibility
    const indexExists = await esClient.indices.exists({
      index: BENCHMARK_SCORE_INDEX_DEFAULT_NS,
    });

    if (indexExists) {
      // Verify that existing index has correct mapping
      const isMappingCompatible = await verifyIndexMappingCompatibility(
        esClient,
        BENCHMARK_SCORE_INDEX_DEFAULT_NS,
        benchmarkScoreMapping,
        logger
      );

      if (!isMappingCompatible) {
        logger.warn(
          `Score index mapping is incompatible with expected mapping. Recreating index [Name: ${BENCHMARK_SCORE_INDEX_DEFAULT_NS}]`
        );
        await recreateIndexSafe(esClient, logger, BENCHMARK_SCORE_INDEX_DEFAULT_NS);
      } else {
        // Try to update mapping for any new fields
        await updateIndexSafe(
          esClient,
          logger,
          BENCHMARK_SCORE_INDEX_DEFAULT_NS,
          benchmarkScoreMapping
        );
      }
    } else {
      // Create new index
      await createIndexSafe(esClient, logger, BENCHMARK_SCORE_INDEX_DEFAULT_NS);
    }

    // Final verification that the index has the correct mapping before allowing ingestion
    await verifyFinalIndexMapping(
      esClient,
      BENCHMARK_SCORE_INDEX_DEFAULT_NS,
      benchmarkScoreMapping,
      logger
    );
  } catch (e) {
    logger.error(e);
    throw Error(
      `Failed to upsert index template [Template: ${BENCHMARK_SCORE_INDEX_TEMPLATE_NAME}]`
    );
  }
};

const createLatestIndex = async (
  esClient: ElasticsearchClient,
  indexConfig: IndexConfig,
  cloudSecurityPostureConfig: CloudSecurityPostureConfig,
  logger: Logger
) => {
  const { indexName, indexPattern, indexTemplateName, indexDefaultName } = indexConfig;
  try {
    // We want that our latest findings index template would be identical to the findings index template
    const indexTemplateResponse = await esClient.indices.getIndexTemplate({
      name: indexName,
    });

    const {
      template,
      _meta,
      // eslint-disable-next-line @typescript-eslint/naming-convention
      composed_of = [],
    } = indexTemplateResponse.index_templates[0].index_template;

    const indexTemplateParams = {
      template,
      composedOf: composed_of,
      _meta,
      indexTemplateName,
      indexPattern,
    };

    // We always want to keep the index template updated
    await updateIndexTemplate(esClient, indexTemplateParams, cloudSecurityPostureConfig, logger);

    const result = await createIndexSafe(esClient, logger, indexDefaultName);

    if (result === 'already-exists') {
      // Make sure mappings are up-to-date
      const simulateResponse = await esClient.indices.simulateTemplate({
        name: indexTemplateName,
      });

      await updateIndexSafe(esClient, logger, indexDefaultName, simulateResponse.template.mappings);
    }
  } catch (e) {
    logger.error(e);
    throw Error(`Failed to upsert index template [Template: ${indexTemplateName}]`);
  }
};

const deleteIndexTemplateSafe = async (
  esClient: ElasticsearchClient,
  logger: Logger,
  name: string
) => {
  try {
    const resp = await esClient.indices.getIndexTemplate({
      name,
    });

    if (resp.index_templates) {
      await esClient.indices.deleteIndexTemplate({
        name,
      });

      logger.info(`Deleted index template successfully [Name: ${name}]`);
    }
  } catch (e) {
    if (e instanceof errors.ResponseError && e.statusCode === 404) {
      logger.trace(`Index template no longer exists [Name: ${name}]`);
    } else {
      logger.error(`Failed to delete index template [Name: ${name}]`);
      logger.error(e);
    }
  }
};

const createIndexSafe = async (esClient: ElasticsearchClient, logger: Logger, index: string) => {
  try {
    const isLatestIndexExists = await esClient.indices.exists({
      index,
    });

    if (!isLatestIndexExists) {
      await esClient.indices.create({
        index,
      });

      logger.info(`Created index successfully [Name: ${index}]`);
      return 'success';
    } else {
      logger.trace(`Index already exists [Name: ${index}]`);
      return 'already-exists';
    }
  } catch (e) {
    logger.error(`Failed to create index [Name: ${index}]`);
    logger.error(e);
    return 'fail';
  }
};

const updateIndexTemplate = async (
  esClient: ElasticsearchClient,
  indexTemplateParams: IndexTemplateParams,
  cloudSecurityPostureConfig: CloudSecurityPostureConfig,
  logger: Logger
) => {
  const { indexTemplateName, indexPattern, template, composedOf, _meta } = indexTemplateParams;

  const settings: IndexTemplateSettings = {
    ...template?.settings, // nothing inside
    index: {
      default_pipeline: latestFindingsPipelineIngestConfig.id,
      codec: 'best_compression',
      mapping: {
        ignore_malformed: true,
      },
    },
    lifecycle: { name: '' },
  };
  if (cloudSecurityPostureConfig.serverless.enabled) delete settings.lifecycle;

  try {
    await esClient.indices.putIndexTemplate({
      name: indexTemplateName,
      index_patterns: indexPattern,
      priority: 500,
      template: {
        mappings: template?.mappings,
        settings,
        aliases: template?.aliases,
      },
      _meta,
      composed_of: composedOf.filter((ct) => ct !== STACK_COMPONENT_TEMPLATE_LOGS_SETTINGS),
      ignore_missing_component_templates: composedOf.filter((templateName) =>
        templateName.endsWith('@custom')
      ),
    });

    logger.info(`Updated index template successfully [Name: ${indexTemplateName}]`);

    // Wait for the template to be available before proceeding
    await waitForIndexTemplate(esClient, indexTemplateName, logger);
  } catch (e) {
    logger.error(`Failed to update index template [Name: ${indexTemplateName}]`);
    logger.error(e);
  }
};

const updateIndexSafe = async (
  esClient: ElasticsearchClient,
  logger: Logger,
  index: string,
  mappings: MappingTypeMapping
) => {
  // for now, remove from object so as not to update stream or data stream properties of the index until type and name
  // are added in https://github.com/elastic/kibana/issues/66551.  namespace value we will continue
  // to skip updating and assume the value in the index mapping is correct
  if (mappings && mappings.properties) {
    delete mappings.properties.stream;
    delete mappings.properties.data_stream;
  }
  try {
    await esClient.indices.putMapping({
      index,
      properties: mappings.properties,
    });
    logger.info(`Updated index successfully [Name: ${index}]`);
  } catch (e) {
    logger.error(`Failed to update index [Name: ${index}]`);
    logger.error(e);
  }
};

/**
 * Waits for an index template to be available in Elasticsearch
 */
const waitForIndexTemplate = async (
  esClient: ElasticsearchClient,
  templateName: string,
  logger: Logger,
  maxRetries: number = 10,
  delayMs: number = 1000
): Promise<void> => {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const response = await esClient.indices.getIndexTemplate({
        name: templateName,
      });

      if (response.index_templates && response.index_templates.length > 0) {
        logger.debug(`Index template is available [Name: ${templateName}]`);
        return;
      }
    } catch (e) {
      if (attempt === maxRetries) {
        logger.error(
          `Index template not available after ${maxRetries} attempts [Name: ${templateName}]`
        );
        throw new Error(`Index template verification timeout: ${templateName}`);
      }
      logger.debug(
        `Waiting for index template (attempt ${attempt}/${maxRetries}) [Name: ${templateName}]`
      );
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
};

/**
 * Verifies that the existing index mapping is compatible with the expected mapping.
 * Focuses on critical fields that could cause issues if they have wrong types.
 */
const verifyIndexMappingCompatibility = async (
  esClient: ElasticsearchClient,
  indexName: string,
  expectedMapping: MappingTypeMapping,
  logger: Logger
): Promise<boolean> => {
  try {
    logger.info(`[MAPPING_CHECK] Starting mapping verification for index: ${indexName}`);

    const response = await esClient.indices.getMapping({
      index: indexName,
    });

    const currentMapping = response[indexName]?.mappings;
    if (!currentMapping || !currentMapping.properties) {
      logger.warn(`[MAPPING_CHECK] No mapping found for index [Name: ${indexName}]`);
      return false;
    }

    logger.info(`[MAPPING_CHECK] Current mapping retrieved, checking critical fields...`);

    // Check critical fields that are known to cause issues when they have wrong types
    const criticalFields = ['namespace', '@timestamp', 'cluster_id', 'resource.id'];
    let hasIssues = false;

    for (const fieldPath of criticalFields) {
      const expectedFieldType = getNestedProperty(expectedMapping.properties, fieldPath);
      const currentFieldType = getNestedProperty(currentMapping.properties, fieldPath);

      logger.info(`[MAPPING_CHECK] Checking field: ${fieldPath}`);
      logger.info(`[MAPPING_CHECK] Expected: ${JSON.stringify(expectedFieldType)}`);
      logger.info(`[MAPPING_CHECK] Current: ${JSON.stringify(currentFieldType)}`);

      // If we expect this field but it doesn't exist in current mapping
      if (expectedFieldType && !currentFieldType) {
        logger.warn(
          `[MAPPING_CHECK] Critical field missing from index mapping: ${fieldPath} [Index: ${indexName}]`
        );
        hasIssues = true;
      }

      // If both fields exist, check if their types are compatible
      if (expectedFieldType && currentFieldType) {
        const expectedType = expectedFieldType.type;
        const currentType = currentFieldType.type;

        if (expectedType && currentType && expectedType !== currentType) {
          logger.warn(
            `[MAPPING_CHECK] Field type mismatch for ${fieldPath}: expected ${expectedType}, got ${currentType} [Index: ${indexName}]`
          );
          hasIssues = true;
        }

        // Special check for namespace field - must be exactly keyword type
        if (fieldPath === 'namespace') {
          if (currentType !== 'keyword') {
            logger.error(
              `[MAPPING_CHECK] CRITICAL: namespace field MUST be keyword type for aggregations to work. Current type: ${currentType} [Index: ${indexName}]`
            );
            hasIssues = true;
          } else {
            logger.info(`[MAPPING_CHECK] ✅ namespace field is correctly set as keyword type`);
          }

          // Also check if it's a text field with keyword subfield (classic race condition symptom)
          if (currentType === 'text' && currentFieldType.fields?.keyword) {
            logger.error(
              `[MAPPING_CHECK] RACE CONDITION DETECTED: namespace is text with keyword subfield. This will cause dashboard aggregation failures! [Index: ${indexName}]`
            );
            logger.error(
              `[MAPPING_CHECK] This is the classic race condition where documents were indexed before template was applied.`
            );
            hasIssues = true;
          }
        }
      }
    }

    if (hasIssues) {
      logger.warn(`[MAPPING_CHECK] Index mapping has issues and needs fixing [Name: ${indexName}]`);
      return false;
    }

    logger.info(`[MAPPING_CHECK] Index mapping is compatible [Name: ${indexName}]`);
    return true;
  } catch (e) {
    logger.error(
      `[MAPPING_CHECK] Failed to verify index mapping compatibility [Name: ${indexName}]: ${e}`
    );
    return false;
  }
};

/**
 * Helper function to get nested properties from mapping object
 */
const getNestedProperty = (obj: any, path: string): any => {
  return path.split('.').reduce((current, key) => {
    return current && current[key] ? current[key] : undefined;
  }, obj);
};

/**
 * Safely recreates an index by deleting and creating it again
 */
const recreateIndexSafe = async (
  esClient: ElasticsearchClient,
  logger: Logger,
  indexName: string
): Promise<void> => {
  try {
    // Delete the existing index
    await esClient.indices.delete({
      index: indexName,
    });
    logger.info(`Deleted existing index [Name: ${indexName}]`);

    // Create the index again (will use the updated template)
    await esClient.indices.create({
      index: indexName,
    });
    logger.info(`Recreated index successfully [Name: ${indexName}]`);
  } catch (e) {
    logger.error(`Failed to recreate index [Name: ${indexName}]: ${e}`);
    throw e;
  }
};

/**
 * Final verification that the index has the correct mapping before allowing ingestion
 */
const verifyFinalIndexMapping = async (
  esClient: ElasticsearchClient,
  indexName: string,
  expectedMapping: MappingTypeMapping,
  logger: Logger
): Promise<void> => {
  const isCompatible = await verifyIndexMappingCompatibility(
    esClient,
    indexName,
    expectedMapping,
    logger
  );

  if (!isCompatible) {
    throw new Error(
      `Index mapping verification failed. Cannot proceed with ingestion until mapping is corrected [Index: ${indexName}]`
    );
  }

  logger.info(`Index mapping verification passed [Name: ${indexName}]`);
};

/**
 * Exported function to verify and fix benchmark score index mapping if needed
 * This can be used by external tasks before they attempt to index documents
 * Returns true if safe to proceed with indexing, false if current run should be skipped
 */
export const ensureBenchmarkScoreIndexMapping = async (
  esClient: ElasticsearchClient,
  logger: Logger
): Promise<boolean> => {
  logger.info(`[INDEX_FIX] Starting benchmark score index mapping verification and fix`);

  try {
    // Check if the index exists
    const indexExists = await esClient.indices.exists({
      index: BENCHMARK_SCORE_INDEX_DEFAULT_NS,
    });

    logger.info(
      `[INDEX_FIX] Index exists check: ${indexExists} [Name: ${BENCHMARK_SCORE_INDEX_DEFAULT_NS}]`
    );

    if (!indexExists) {
      logger.info(
        `[INDEX_FIX] Benchmark score index does not exist, will be created automatically on first document [Name: ${BENCHMARK_SCORE_INDEX_DEFAULT_NS}]`
      );

      // Let's also verify that the template exists and has correct mapping
      try {
        logger.info(`[INDEX_FIX] Verifying index template exists and has correct mapping...`);
        const templateResponse = await esClient.indices.getIndexTemplate({
          name: BENCHMARK_SCORE_INDEX_TEMPLATE_NAME,
        });

        if (templateResponse.index_templates && templateResponse.index_templates.length > 0) {
          const template = templateResponse.index_templates[0];
          const templateMapping = template.index_template.template?.mappings;
          const namespaceField = getNestedProperty(templateMapping?.properties, 'namespace');

          logger.info(
            `[INDEX_FIX] Template found. Namespace field in template: ${JSON.stringify(
              namespaceField
            )}`
          );

          if (namespaceField?.type === 'keyword') {
            logger.info(
              `[INDEX_FIX] Template has correct namespace mapping. Index will be created correctly.`
            );
          } else if (!namespaceField) {
            logger.error(
              `[INDEX_FIX] CRITICAL: Template is missing namespace field! This will cause race condition.`
            );
            logger.info(
              `[INDEX_FIX] Attempting to fix template by updating it with correct mapping...`
            );

            try {
              // Update the template with the correct mapping
              await esClient.indices.putIndexTemplate({
                name: BENCHMARK_SCORE_INDEX_TEMPLATE_NAME,
                index_patterns: BENCHMARK_SCORE_INDEX_PATTERN,
                template: {
                  mappings: benchmarkScoreMapping,
                  settings: {
                    index: {
                      default_pipeline: scorePipelineIngestConfig.id,
                    },
                    lifecycle: { name: '' },
                  },
                },
                _meta: {
                  package: {
                    name: CLOUD_SECURITY_POSTURE_PACKAGE_NAME,
                  },
                  managed_by: 'cloud_security_posture',
                  managed: true,
                },
                priority: 500,
              });

              logger.info(`[INDEX_FIX] Successfully updated template with namespace field!`);

              // Wait for template to be available
              await waitForIndexTemplate(esClient, BENCHMARK_SCORE_INDEX_TEMPLATE_NAME, logger);
            } catch (e) {
              logger.error(`[INDEX_FIX] Failed to update template: ${e}`);
              logger.error(
                `[INDEX_FIX] Template fix failed. Restart Kibana or manually update template.`
              );
            }
          } else {
            logger.error(
              `[INDEX_FIX] CRITICAL: Template namespace field is NOT keyword! Current type: ${
                namespaceField?.type || 'undefined'
              }`
            );
            logger.error(
              `[INDEX_FIX] This will cause dashboard aggregation failures. Expected: keyword, Got: ${namespaceField?.type}`
            );
            logger.info(
              `[INDEX_FIX] Attempting to fix template by updating it with correct keyword mapping...`
            );

            try {
              // Update the template with the correct mapping
              await esClient.indices.putIndexTemplate({
                name: BENCHMARK_SCORE_INDEX_TEMPLATE_NAME,
                index_patterns: BENCHMARK_SCORE_INDEX_PATTERN,
                template: {
                  mappings: benchmarkScoreMapping,
                  settings: {
                    index: {
                      default_pipeline: scorePipelineIngestConfig.id,
                    },
                    lifecycle: { name: '' },
                  },
                },
                _meta: {
                  package: {
                    name: CLOUD_SECURITY_POSTURE_PACKAGE_NAME,
                  },
                  managed_by: 'cloud_security_posture',
                  managed: true,
                },
                priority: 500,
              });

              logger.info(
                `[INDEX_FIX] Successfully fixed template - namespace is now keyword type!`
              );

              // Wait for template to be available
              await waitForIndexTemplate(esClient, BENCHMARK_SCORE_INDEX_TEMPLATE_NAME, logger);
            } catch (e) {
              logger.error(`[INDEX_FIX] Failed to fix template: ${e}`);
              logger.error(
                `[INDEX_FIX] Template fix failed. Restart Kibana or manually update template.`
              );
            }
          }
        } else {
          logger.error(
            `[INDEX_FIX] CRITICAL: Index template not found! Template needs to be created during startup.`
          );
        }
      } catch (e) {
        logger.warn(`[INDEX_FIX] Could not verify template: ${e}`);
      }

      // Index will be created automatically when first document is indexed
      // This is normal behavior and safe to proceed
      return true;
    }

    logger.info(`[INDEX_FIX] Index exists, verifying mapping compatibility...`);

    // Verify that existing index has correct mapping
    const isMappingCompatible = await verifyIndexMappingCompatibility(
      esClient,
      BENCHMARK_SCORE_INDEX_DEFAULT_NS,
      benchmarkScoreMapping,
      logger
    );

    logger.info(`[INDEX_FIX] Mapping compatibility result: ${isMappingCompatible}`);

    if (!isMappingCompatible) {
      logger.warn(
        `[INDEX_FIX] Benchmark score index mapping is incompatible. Attempting to fix [Name: ${BENCHMARK_SCORE_INDEX_DEFAULT_NS}]`
      );

      try {
        logger.info(`[INDEX_FIX] Starting index recreation process...`);

        // Try to recreate the index with correct mapping
        await recreateIndexSafe(esClient, logger, BENCHMARK_SCORE_INDEX_DEFAULT_NS);

        logger.info(`[INDEX_FIX] Index recreation completed, verifying final mapping...`);

        // Verify the mapping is now correct
        await verifyFinalIndexMapping(
          esClient,
          BENCHMARK_SCORE_INDEX_DEFAULT_NS,
          benchmarkScoreMapping,
          logger
        );

        logger.info(
          `[INDEX_FIX] Successfully fixed benchmark score index mapping [Name: ${BENCHMARK_SCORE_INDEX_DEFAULT_NS}]`
        );
        return true;
      } catch (e) {
        logger.error(
          `[INDEX_FIX] Failed to fix benchmark score index mapping [Name: ${BENCHMARK_SCORE_INDEX_DEFAULT_NS}]: ${e}`
        );
        // Return false to skip THIS run, but allow next run to try again
        logger.warn(
          `[INDEX_FIX] Skipping score indexing for this run. Will retry on next scheduled run in 5 minutes.`
        );
        return false;
      }
    }

    logger.info(
      `[INDEX_FIX] Benchmark score index mapping is compatible [Name: ${BENCHMARK_SCORE_INDEX_DEFAULT_NS}]`
    );
    return true;
  } catch (e) {
    logger.error(
      `[INDEX_FIX] Error checking benchmark score index mapping [Name: ${BENCHMARK_SCORE_INDEX_DEFAULT_NS}]: ${e}`
    );
    // Return false to skip THIS run, but allow next run to try again
    logger.warn(
      `[INDEX_FIX] Skipping score indexing for this run due to verification error. Will retry on next scheduled run in 5 minutes.`
    );
    return false;
  }
};

/**
 * Lightweight function to verify benchmark score index mapping before querying
 * This can be used by dashboard/API endpoints to prevent aggregation errors
 * Returns true if safe to query, false if there are mapping issues
 */
export const verifyBenchmarkScoreIndexForQuery = async (
  esClient: ElasticsearchClient,
  logger: Logger
): Promise<boolean> => {
  try {
    // Check if the index exists
    const indexExists = await esClient.indices.exists({
      index: BENCHMARK_SCORE_INDEX_DEFAULT_NS,
    });

    if (!indexExists) {
      logger.debug(
        `Benchmark score index does not exist [Name: ${BENCHMARK_SCORE_INDEX_DEFAULT_NS}]`
      );
      return false; // Can't query an index that doesn't exist
    }

    // Verify that existing index has correct mapping for critical fields
    const isMappingCompatible = await verifyIndexMappingCompatibility(
      esClient,
      BENCHMARK_SCORE_INDEX_DEFAULT_NS,
      benchmarkScoreMapping,
      logger
    );

    if (!isMappingCompatible) {
      logger.warn(
        `Benchmark score index has incompatible mapping. Dashboard queries may fail [Name: ${BENCHMARK_SCORE_INDEX_DEFAULT_NS}]`
      );
      return false;
    }

    return true;
  } catch (e) {
    logger.error(
      `Error verifying benchmark score index for query [Name: ${BENCHMARK_SCORE_INDEX_DEFAULT_NS}]: ${e}`
    );
    return false;
  }
};
