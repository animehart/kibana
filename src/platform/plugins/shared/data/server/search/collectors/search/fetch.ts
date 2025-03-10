/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { CollectorFetchContext } from '@kbn/usage-collection-plugin/server';
import { CollectedUsage, ReportedUsage } from './register';

interface SearchTelemetry {
  'search-telemetry': CollectedUsage;
}

export function fetchProvider(getIndexForType: (type: string) => Promise<string>) {
  return async ({ esClient }: CollectorFetchContext): Promise<ReportedUsage> => {
    const searchIndex = await getIndexForType('search-telemetry');
    const esResponse = await esClient.search<SearchTelemetry>(
      {
        index: searchIndex,
        query: { term: { type: { value: 'search-telemetry' } } },
      },
      { ignore: [404] }
    );
    const size = esResponse?.hits?.hits?.length ?? 0;
    if (!size) {
      return {
        successCount: 0,
        errorCount: 0,
        averageDuration: null,
      };
    }
    const { successCount, errorCount, totalDuration } =
      esResponse.hits.hits[0]._source!['search-telemetry'];
    const averageDuration = totalDuration / successCount;
    return { successCount, errorCount, averageDuration };
  };
}
