/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { HttpHandler } from '@kbn/core/public';
import type { estypes } from '@elastic/elasticsearch';

import { decodeOrThrow } from '@kbn/io-ts-utils';
import type { ValidationIndicesFieldSpecification } from '../../../../../common/http_api';
import {
  LOG_ANALYSIS_VALIDATE_INDICES_PATH,
  validationIndicesRequestPayloadRT,
  validationIndicesResponsePayloadRT,
} from '../../../../../common/http_api';

interface RequestArgs {
  indices: string[];
  fields: ValidationIndicesFieldSpecification[];
  runtimeMappings: estypes.MappingRuntimeFields;
}

export const callValidateIndicesAPI = async (requestArgs: RequestArgs, fetch: HttpHandler) => {
  const { indices, fields, runtimeMappings } = requestArgs;
  const response = await fetch(LOG_ANALYSIS_VALIDATE_INDICES_PATH, {
    method: 'POST',
    body: JSON.stringify(
      // @ts-expect-error TODO: fix after elasticsearch-js bump
      validationIndicesRequestPayloadRT.encode({ data: { indices, fields, runtimeMappings } })
    ),
    version: '1',
  });

  return decodeOrThrow(validationIndicesResponsePayloadRT)(response);
};
