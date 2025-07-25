/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from '@kbn/zod';
import { builtinToolIds, builtinTags } from '@kbn/onechat-common';
import type { BuiltinToolDefinition } from '@kbn/onechat-server';
import { listIndices, ListIndexInfo } from '@kbn/onechat-genai-utils';

const listIndicesSchema = z.object({
  pattern: z
    .string()
    .optional()
    .describe(
      '(optional) pattern to filter indices by. Defaults to *. Leave empty to list all indices (recommended)'
    ),
});

export interface ListIndexResponse {
  indices: ListIndexInfo[];
}

export const listIndicesTool = (): BuiltinToolDefinition<
  typeof listIndicesSchema,
  ListIndexResponse
> => {
  return {
    id: builtinToolIds.listIndices,
    description: 'List the indices in the Elasticsearch cluster the current user has access to.',
    schema: listIndicesSchema,
    handler: async ({ pattern = '*' }, { esClient }) => {
      const result = await listIndices({ pattern, esClient: esClient.asCurrentUser });
      return {
        result: {
          indices: result,
        },
      };
    },
    tags: [builtinTags.retrieval],
  };
};
