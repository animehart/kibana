/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useQuery } from '@tanstack/react-query';
import type { ListResult } from '@kbn/fleet-plugin/common';
import { BENCHMARKS_ROUTE_PATH } from '../../../common/constants';
import type { BenchmarksQueryParams } from '../../../common/schemas/benchmark';
import { useKibana } from '../../common/hooks/use_kibana';
import type { Benchmark, BenchmarkVersion2 } from '../../../common/types_old';

const QUERY_KEY = 'csp_benchmark_integrations';

export interface UseCspBenchmarkIntegrationsProps {
  name: string;
  page: number;
  perPage: number;
  sortField: BenchmarksQueryParams['sort_field'];
  sortOrder: BenchmarksQueryParams['sort_order'];
}

export interface BenchmarkDetails extends ListResult<BenchmarkVersion2> {
  items_policies_information: Benchmark[];
}
export const useCspBenchmarkIntegrations = ({
  name,
  perPage,
  page,
  sortField,
  sortOrder,
}: UseCspBenchmarkIntegrationsProps) => {
  const { http } = useKibana().services;
  const query: BenchmarksQueryParams = {
    package_policy_name: name,
    per_page: perPage,
    page,
    sort_field: sortField,
    sort_order: sortOrder,
  };

  return useQuery(
    [QUERY_KEY, query],
    () =>
      http.get<BenchmarkDetails>(BENCHMARKS_ROUTE_PATH, {
        query,
        version: '2',
      }),
    { keepPreviousData: true }
  );
};
