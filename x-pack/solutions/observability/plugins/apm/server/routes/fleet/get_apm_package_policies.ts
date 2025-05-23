/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { CoreStart, SavedObjectsClientContract } from '@kbn/core/server';
import type { APMPluginStartDependencies } from '../../types';
import { getInternalSavedObjectsClient } from '../../lib/helpers/get_internal_saved_objects_client';

export async function getApmPackagePolicies({
  coreStart,
  fleetPluginStart,
}: {
  coreStart: CoreStart;
  fleetPluginStart: NonNullable<APMPluginStartDependencies['fleet']>;
}) {
  const savedObjectsClient: SavedObjectsClientContract = await getInternalSavedObjectsClient(
    coreStart
  );
  return await fleetPluginStart.packagePolicyService.list(savedObjectsClient, {
    kuery: 'ingest-package-policies.package.name:apm',
    spaceId: '*',
  });
}
