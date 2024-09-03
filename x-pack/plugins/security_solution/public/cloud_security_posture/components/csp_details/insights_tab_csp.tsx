/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { memo, useCallback, useState } from 'react';
import type { EuiBasicTableColumn } from '@elastic/eui';
import {
  EuiBadge,
  EuiBasicTable,
  EuiButtonGroup,
  EuiSpacer,
  type EuiBadgeProps,
  EuiIcon,
  EuiPanel,
  EuiLink,
} from '@elastic/eui';
import { useMisconfigurationFindings } from '@kbn/cloud-security-posture/src/hooks/use_misconfiguration_findings';
import type { EuiButtonGroupOptionProps } from '@elastic/eui/src/components/button/button_group/button_group';
import { i18n } from '@kbn/i18n';
import { FormattedMessage } from '@kbn/i18n-react';
import { useExpandableFlyoutState } from '@kbn/expandable-flyout';
import { buildEntityFlyoutPreviewQuery } from '@kbn/cloud-security-posture-common';
import { euiThemeVars } from '@kbn/ui-theme';
import { css } from '@emotion/react';
import { DistributionBar } from '@kbn/security-solution-distribution-bar';
import { useNavigateFindings } from '@kbn/cloud-security-posture/src/hooks/use_navigate_findings';

const getFindingsStats = (passedFindingsStats: number, failedFindingsStats: number) => {
  if (passedFindingsStats === 0 && failedFindingsStats === 0) return [];
  return [
    {
      key: i18n.translate(
        'xpack.securitySolution.flyout.right.insights.misconfigurations.passedFindingsText',
        {
          defaultMessage: 'Passed findings',
        }
      ),
      count: passedFindingsStats,
      color: euiThemeVars.euiColorSuccess,
    },
    {
      key: i18n.translate(
        'xpack.securitySolution.flyout.right.insights.misconfigurations.failedFindingsText',
        {
          defaultMessage: 'Failed findings',
        }
      ),
      count: failedFindingsStats,
      color: euiThemeVars.euiColorVis9,
    },
  ];
};

interface Props {
  type?: 'passed' | 'failed';
}
const BADGE_WIDTH = '46px';
export const statusColors = {
  passed: euiThemeVars.euiColorSuccess,
  failed: euiThemeVars.euiColorVis9,
};

const getColor = (type: Props['type']): EuiBadgeProps['color'] => {
  if (type === 'passed') return statusColors.passed;
  if (type === 'failed') return statusColors.failed;
  return 'default';
};

export const CspEvaluationBadge = ({ type }: Props) => (
  <EuiBadge
    color={getColor(type)}
    css={css`
      width: ${BADGE_WIDTH};
      display: flex;
      justify-content: center;
    `}
    data-test-subj={`${type}_finding`}
  >
    {type === 'failed' ? (
      <FormattedMessage id="xpack.csp.cspEvaluationBadge.failLabel" defaultMessage="Fail" />
    ) : type === 'passed' ? (
      <FormattedMessage id="xpack.csp.cspEvaluationBadge.passLabel" defaultMessage="Pass" />
    ) : (
      <FormattedMessage id="xpack.csp.cspEvaluationBadge.naLabel" defaultMessage="N/A" />
    )}
  </EuiBadge>
);

const insightsButtons: EuiButtonGroupOptionProps[] = [
  {
    id: 'misconfigurationTabId',
    label: (
      <FormattedMessage
        id="xpack.securitySolution.flyout.left.insights.threatIntelligenceButtonLabel"
        defaultMessage="Misconfiguration"
      />
    ),
    'data-test-subj': 'misconfigurationTabDataTestId',
  },
];

interface Finding {
  result: string;
  rule: string;
}

/**
 * Insights view displayed in the document details expandable flyout left section
 */
export const InsightsTabCsp = memo(({ name }: { name: string }) => {
  //   const { eventId, indexName, scopeId, getFieldsData } = useDocumentDetailsContext();
  //   const isEventKindSignal = getField(getFieldsData('event.kind')) === EventKind.signal;
  //   const { openLeftPanel } = useExpandableFlyoutApi();
  const panels = useExpandableFlyoutState();
  const activeInsightsId = panels.left?.path?.subTab ?? 'misconfigurationTabId';
  const { data } = useMisconfigurationFindings({
    query: buildEntityFlyoutPreviewQuery('host.name', name),
    sort: [],
    enabled: true,
    pageSize: 1,
  });
  //   const rows = useMemo(() => getRowsFromPages(data?.pages), [data?.pages]);
  const passedFindings = data?.count.passed || 0;
  const failedFindings = data?.count.failed || 0;
  console.log(data)
  const rows = data?.page?.map((finding) => ({
    result: finding?.raw?._source?.result.evaluation,
    rule: finding?.raw?._source?.rule.name,
  }));

  const rowsDatagrid = data?.page?.map((finding) => ({
    link: <EuiIcon type={'popout'} />,
    result: <CspEvaluationBadge type={finding?.raw?._source?.result.evaluation} />,
    rule: finding?.raw?._source?.rule.name,
  }));

  const columns: Array<EuiBasicTableColumn<Finding>> = [
    {
      field: 'result',
      render: (status: Finding['result']) => <EuiIcon type={'popout'} />,
      name: '',
      width: '5%',
    },
    {
      field: 'result',
      render: (status: Finding['result']) => <CspEvaluationBadge type={status} />,
      name: 'Result',
      width: '10%',
    },
    {
      field: 'rule',
      name: 'Rule',
      width: '90%',
    },
  ];

  const columnsDataGrid = [
    {
      id: 'link',
      displayAsText: ' ',
      initialWidth: 40,
    },
    {
      id: 'result',
      displayAsText: 'Result',
      initialWidth: 70,
    },
    {
      id: 'rule',
      displayAsText: 'Rule',
      initialWidth: 800,
    },
  ];

  const findings: Finding[] = [
    {
      result: 'pass',
      rule: ' Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum',
    },
    {
      result: 'fail',
      rule: ' Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum',
    },
  ];

  const [pageIndex, setPageIndex] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [showPerPageOptions, setShowPerPageOptions] = useState(true);

  const findUsers = (users: Finding[], pageIndex: number, pageSize: number) => {
    let pageOfItems;

    if (!pageIndex && !pageSize) {
      pageOfItems = users;
    } else {
      const startIndex = pageIndex * pageSize;
      pageOfItems = users?.slice(startIndex, Math.min(startIndex + pageSize, users?.length));
    }

    return {
      pageOfItems,
      totalItemCount: users?.length,
    };
  };

  const { pageOfItems, totalItemCount } = findUsers(rows, pageIndex, pageSize);

  const pagination = {
    pageIndex,
    pageSize,
    totalItemCount,
    pageSizeOptions: [10, 0],
    showPerPageOptions,
  };

  const onTableChange = ({ page }: Criteria<Finding>) => {
    if (page) {
      const { index: pageIndex, size: pageSize } = page;
      setPageIndex(pageIndex);
      setPageSize(pageSize);
    }
  };
  const [visibleColumns, setVisibleColumns] = useState(
    columnsDataGrid.map(({ id }) => id) // initialize to the full set of columns
  );

  const navToFindings = useNavigateFindings();

  const navToFindingsByHostName = (hostName: string) => {
    navToFindings({ 'host.name': hostName }, ['rule.name']);
  };

  //Pagination stuffs for datagrid

  const [paginations, setPagination] = useState({ pageIndex: 0 });
  const onChangeItemsPerPage = useCallback(
    (pageSize) =>
      setPagination((paginationss) => ({
        ...paginationss,
        pageSize,
        pageIndex: 0,
      })),
    [setPagination]
  );
  const onChangePage = useCallback(
    (pageIndex) => setPagination((paginationsx) => ({ ...paginationsx, pageIndex })),
    [setPagination]
  );

  // const navToFindings = useNavigateFindings();
  // const navToFindingsByHostName = (hostName: string) => {
  //   navToFindings({ 'host.name': hostName });
  // };
  return (
    <>
      <EuiButtonGroup
        color="primary"
        legend={i18n.translate(
          'xpack.securitySolution.flyout.left.insights.buttonGroupLegendLabel',
          { defaultMessage: 'Insights options' }
        )}
        options={insightsButtons}
        idSelected={activeInsightsId}
        onChange={() => {}}
        buttonSize="compressed"
        isFullWidth
        data-test-subj={'TEST TEST ETS'}
      />
      <EuiSpacer size="xl" />
      <EuiPanel hasShadow={false}>
        <EuiLink
          onClick={() => {
            navToFindingsByHostName(name);
          }}
        >
          {'Misconfigurations'}
          <EuiIcon type={'popout'} />
        </EuiLink>
        <EuiSpacer size="xl" />
        {/* {activeInsightsId === ENTITIES_TAB_ID && <EntitiesDetails />}
      {activeInsightsId === THREAT_INTELLIGENCE_TAB_ID && <ThreatIntelligenceDetails />}
      {activeInsightsId === PREVALENCE_TAB_ID && <PrevalenceDetails />}
      {activeInsightsId === CORRELATIONS_TAB_ID && <CorrelationsDetails />} */}
        {/* <div>{`${field}:${query}`}</div> */}
        <DistributionBar stats={getFindingsStats(passedFindings, failedFindings)} />

        <EuiBasicTable
          tableCaption="MUAHAHAHAH"
          items={pageOfItems || []}
          rowHeader="result"
          columns={columns}
          pagination={pagination}
          onChange={onTableChange}
        />
        {/* <EuiDataGrid
          aria-label="misconfigurationDataGrid"
          columns={columnsDataGrid}
          renderCellValue={({ rowIndex, columnId }) => {
            return rowsDatagrid?.[rowIndex]?.[columnId] || null;
          }}
          columnVisibility={{ visibleColumns, setVisibleColumns }}
          toolbarVisibility={false}
          rowCount={rowsDatagrid?.length || 0}
          gridStyle={{
            border: 'horizontal',
            stripes: true,
            rowHover: 'highlight',
            header: 'underline',
            cellPadding: 'l',
          }}
          pagination={{
            ...paginations,
            onChangeItemsPerPage,
            onChangePage,
          }}
        /> */}
      </EuiPanel>
    </>
  );
});

InsightsTabCsp.displayName = 'InsightsTab';
