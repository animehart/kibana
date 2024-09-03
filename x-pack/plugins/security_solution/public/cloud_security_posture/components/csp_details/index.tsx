/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { FC } from 'react';
import React, { memo, useMemo } from 'react';

// import { FlyoutPanelProps, useExpandableFlyoutApi } from '@kbn/expandable-flyout';
import { useExpandableFlyoutApi, type FlyoutPanelProps } from '@kbn/expandable-flyout';
import { useDocumentDetailsContext } from '../../../flyout/document_details/shared/context';
import { PanelHeaderCsp } from './panel_header_csp';
import { PanelContentCsp } from './panel_content_csp';
import { useIsExperimentalFeatureEnabled } from '../../../common/hooks/use_experimental_features';
// import { DocumentDetailsLeftPanelKey } from '../shared/constants/panel_keys';
import { useKibana } from '../../../common/lib/kibana';
// import { PanelHeader } from './header';
// import { PanelContent } from './content';
// import type { LeftPanelTabType } from './tabs';
import * as tabs from './tabs';
import { useCspDetailsContext } from './context';
import { getField } from '../../../flyout/document_details/shared/utils';
// import { getField } from '../shared/utils';
// import { EventKind } from '../shared/constants/event_kinds';
// import { useDocumentDetailsContext } from '../shared/context';
// import type { DocumentDetailsProps } from '../shared/types';
// import { LeftPanelTour } from './components/tour';

export interface CspDocumentDetailsProps extends FlyoutPanelProps {
  // path?: PanelPath;
  params?: {
    id: string;
    indexName: string;
    scopeId: string;
    isPreviewMode?: boolean;
    type: 'Misconfiguration' | 'Vulnerabilities';
    field: 'user.name' | 'host.name';
    query: string;
  };
}

export type LeftPanelPaths = 'visualize' | 'insights' | 'investigation' | 'response' | 'notes';
export const LeftPanelVisualizeTab: LeftPanelPaths = 'visualize';
export const LeftPanelInsightsTab: LeftPanelPaths = 'insights';
export const LeftPanelInvestigationTab: LeftPanelPaths = 'investigation';
export const LeftPanelResponseTab: LeftPanelPaths = 'response';
export const LeftPanelNotesTab: LeftPanelPaths = 'notes';

export const CspLeftPanel: FC<Partial<CspDocumentDetailsProps>> = memo(
  ({ field, query, passedFindings, failedFindings }) => {
    // const { telemetry } = useKibana().services;
    const { openLeftPanel } = useExpandableFlyoutApi();
    // const { eventId, indexName, scopeId } = useCspDetailsContext();
    // console.log(indexName)
    // console.log(scopeId)
    const { eventId, indexName, scopeId, getFieldsData, isPreview } = useCspDetailsContext();

    console.log(getField(getFieldsData('host.name')));
    // const eventKind = getField(getFieldsData('event.kind'));

    const securitySolutionNotesEnabled = useIsExperimentalFeatureEnabled(
      'securitySolutionNotesEnabled'
    );
    const tabsDisplayed = useMemo(() => [tabs.insightsTab], []);
    // const tabsDisplayed = useMemo(() => {
    //   const tabList =
    //     eventKind === EventKind.signal
    //       ? [tabs.insightsTab, tabs.investigationTab, tabs.responseTab]
    //       : [tabs.insightsTab];
    //   if (securitySolutionNotesEnabled && !isPreview) {
    //     tabList.push(tabs.notesTab);
    //   }
    //   return tabList;
    // }, [eventKind, isPreview, securitySolutionNotesEnabled]);

    // const selectedTabId = useMemo(() => {
    //   const defaultTab = tabsDisplayed[0].id;
    //   if (!path) return defaultTab;
    //   return tabsDisplayed.map((tab) => tab.id).find((tabId) => tabId === path.tab) ?? defaultTab;
    // }, [tabsDisplayed]);

    const selectedTabId = 'Insights';

    const setSelectedTabId = (tabId: LeftPanelTabType['id']) => {
      openLeftPanel({
        id: 'CspPanelKey',
        path: {
          tab: tabId,
        },
        params: {
          id: 'A',
          indexName: 'A',
          scopeId: 'A',
        },
      });
    };

    return (
      <>
        {/* <LeftPanelTour /> */}
        <PanelHeaderCsp
          selectedTabId={selectedTabId}
          setSelectedTabId={setSelectedTabId}
          tabs={tabsDisplayed}
        />
        <PanelContentCsp selectedTabId={selectedTabId} tabs={tabsDisplayed} />
        <div>{field}</div>
        <div>{query}</div>
        <div>{passedFindings}</div>
        <div>{failedFindings}</div>
      </>
    );
  }
);

CspLeftPanel.displayName = 'CspLeftPanel';
