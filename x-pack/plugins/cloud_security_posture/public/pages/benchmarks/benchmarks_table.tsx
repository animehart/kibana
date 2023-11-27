/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  EuiBasicTable,
  type EuiBasicTableColumn,
  type EuiBasicTableProps,
  type Pagination,
  type CriteriaWithPagination,
  EuiEmptyPrompt,
  EuiFlexGroup,
  EuiFlexItem,
} from '@elastic/eui';
import React from 'react';
import { i18n } from '@kbn/i18n';
import { FormattedMessage } from '@kbn/i18n-react';

import type { BenchmarkVersion2, BenchmarkScore } from '../../../common/types';
import * as TEST_SUBJ from './test_subjects';
import { isCommonError } from '../../components/cloud_posture_page';
import { FullSizeCenteredPage } from '../../components/full_size_centered_page';
import { ComplianceScoreBar } from '../../components/compliance_score_bar';
import {
  getBenchmarkCisName,
  getBenchmarkApplicableTo,
  getBenchmarkPlurals,
} from '../../../common/utils/helpers';
import { CISBenchmarkIcon } from '../../components/cis_benchmark_icon';

export const ERROR_STATE_TEST_SUBJECT = 'benchmark_page_error';

interface BenchmarksTableProps
  extends Pick<
      EuiBasicTableProps<BenchmarkVersion2>,
      'loading' | 'error' | 'noItemsMessage' | 'sorting'
    >,
    Pagination {
  benchmarks: BenchmarkVersion2[];
  setQuery(pagination: CriteriaWithPagination<BenchmarkVersion2>): void;
  'data-test-subj'?: string;
}

// Commented Out until the full table is made
// const AgentPolicyButtonLink = ({ name, id: policyId }: { name: string; id: string }) => {
//   const { http } = useKibana().services;
//   const [fleetBase, path] = pagePathGetters.policy_details({ policyId });

//   return <EuiLink href={http.basePath.prepend([fleetBase, path].join(''))}>{name}</EuiLink>;
// };

// const IntegrationButtonLink = ({
//   packageName,
//   policyId,
//   packagePolicyId,
// }: {
//   packageName: string;
//   packagePolicyId: string;
//   policyId: string;
// }) => {
//   const { application } = useKibana().services;

//   return (
//     <EuiLink
//       href={application.getUrlForApp('security', {
//         path: generatePath(benchmarksNavigation.rules.path, {
//           packagePolicyId,
//           policyId,
//         }),
//       })}
//     >
//       {packageName}
//     </EuiLink>
//   );
// };

const ErrorMessageComponent = (error: { error: unknown }) => (
  <FullSizeCenteredPage>
    <EuiEmptyPrompt
      color="danger"
      iconType="warning"
      data-test-subj={ERROR_STATE_TEST_SUBJECT}
      title={
        <h2>
          <FormattedMessage
            id="xpack.csp.benchmarks.benchmarksTable.errorRenderer.errorTitle"
            defaultMessage="We couldn't fetch your cloud security posture benchmark data"
          />
        </h2>
      }
      body={
        isCommonError(error) ? (
          <p>
            <FormattedMessage
              id="xpack.csp.benchmarks.benchmarksTable.errorRenderer.errorDescription"
              defaultMessage="{error} {statusCode}: {body}"
              values={{
                error: error.body.error,
                statusCode: error.body.statusCode,
                body: error.body.message,
              }}
            />
          </p>
        ) : undefined
      }
    />
  </FullSizeCenteredPage>
);

const BENCHMARKS_TABLE_COLUMNS_VERSION_2: Array<EuiBasicTableColumn<BenchmarkVersion2>> = [
  {
    field: 'benchmark_id',
    name: i18n.translate('xpack.csp.benchmarks.benchmarksTable.integrationBenchmarkCisName', {
      defaultMessage: 'Benchmark',
    }),
    truncateText: true,
    width: '17.5%',
    sortable: true,
    render: (benchmarkId: string) => {
      return getBenchmarkCisName(benchmarkId);
    },
    'data-test-subj': TEST_SUBJ.BENCHMARKS_TABLE_COLUMNS.CIS_NAME,
  },
  {
    field: 'benchmark_version',
    name: i18n.translate('xpack.csp.benchmarks.benchmarksTable.integrationBenchmarkVersion', {
      defaultMessage: 'Version',
    }),
    truncateText: true,
    sortable: true,
    width: '17.5%',
    'data-test-subj': TEST_SUBJ.BENCHMARKS_TABLE_COLUMNS.VERSION,
  },
  {
    field: 'benchmark_id',
    name: i18n.translate('xpack.csp.benchmarks.benchmarksTable.applicableTo', {
      defaultMessage: 'Applicable To',
    }),
    truncateText: true,
    width: '30%',
    'data-test-subj': TEST_SUBJ.BENCHMARKS_TABLE_COLUMNS.APPLICABLE_TO,
    render: (benchmarkId: string) => {
      return (
        <>
          <EuiFlexGroup gutterSize="s" alignItems="center">
            <EuiFlexItem grow={false}>
              <CISBenchmarkIcon type={benchmarkId} size={'l'} />
            </EuiFlexItem>
            <EuiFlexItem grow={false}>{getBenchmarkApplicableTo(benchmarkId)}</EuiFlexItem>
          </EuiFlexGroup>
        </>
      );
    },
  },
  {
    field: 'benchmark_evaluation',
    name: i18n.translate('xpack.csp.benchmarks.benchmarksTable.evaluated', {
      defaultMessage: 'Evaluated',
    }),
    dataType: 'string',
    truncateText: true,
    width: '17.5%',
    'data-test-subj': TEST_SUBJ.BENCHMARKS_TABLE_COLUMNS.EVALUATED,
    render: (complianceScore: BenchmarkVersion2['benchmark_evaluation'], data) => {
      return getBenchmarkPlurals(data.benchmark_id, data.benchmark_evaluation);
    },
  },
  {
    field: 'benchmark_score',
    name: i18n.translate('xpack.csp.benchmarks.benchmarksTable.score', {
      defaultMessage: 'Compliance',
    }),
    dataType: 'string',
    truncateText: true,
    width: '7.5%',
    'data-test-subj': TEST_SUBJ.BENCHMARKS_TABLE_COLUMNS.COMPLIANCE,
    render: (data: BenchmarkScore) => {
      if (data.totalFindings > 0)
        return (
          <ComplianceScoreBar totalPassed={data?.totalPassed} totalFailed={data?.totalFailed} />
        );
      return (
        <FormattedMessage
          id="xpack.csp.benchmarks.benchmarksTable.noFindingsScore"
          defaultMessage="No Findings"
        />
      );
    },
  },
];

export const BenchmarksTable = ({
  benchmarks,
  pageIndex,
  pageSize,
  totalItemCount,
  loading,
  error,
  setQuery,
  noItemsMessage,
  sorting,
  ...rest
}: BenchmarksTableProps) => {
  const pagination: Pagination = {
    pageIndex: Math.max(pageIndex - 1, 0),
    pageSize,
    totalItemCount,
  };

  const onChange = ({ page }: CriteriaWithPagination<BenchmarkVersion2>) => {
    setQuery({ page: { ...page, index: page.index + 1 } });
  };

  if (error) {
    return <ErrorMessageComponent error={error} />;
  }

  return (
    <EuiBasicTable
      data-test-subj={rest['data-test-subj']}
      items={benchmarks}
      columns={BENCHMARKS_TABLE_COLUMNS_VERSION_2}
      itemId={(item) => [item.benchmark_id, item.benchmark_version].join('/')}
      pagination={pagination}
      onChange={onChange}
      tableLayout="fixed"
      loading={loading}
      noItemsMessage={noItemsMessage}
      error={error}
      /* Disabled Sorting until we have the final Benchmark table */
      // sorting={sorting}
    />
  );
};
