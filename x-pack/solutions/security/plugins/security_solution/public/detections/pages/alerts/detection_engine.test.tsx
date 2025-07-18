/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { render, waitFor } from '@testing-library/react';
import { useParams } from 'react-router-dom';
import { createMockStore, mockGlobalState, TestProviders } from '../../../common/mock';
import { useUserData } from '../../components/user_info';
import { useSourcererDataView } from '../../../sourcerer/containers';
import type { State } from '../../../common/store';
import { mockHistory, Router } from '../../../common/mock/router';
import { mockTimelines } from '../../../common/mock/mock_timelines_plugin';
import { mockBrowserFields } from '../../../common/containers/source/mock';
import { mockCasesContext } from '@kbn/cases-plugin/public/mocks/mock_cases_context';
import { createFilterManagerMock } from '@kbn/data-plugin/public/query/filter_manager/filter_manager.mock';
import { dataViewPluginMocks } from '@kbn/data-views-plugin/public/mocks';
import { createStubDataView } from '@kbn/data-views-plugin/common/data_view.stub';
import { useListsConfig } from '../../containers/detection_engine/lists/use_lists_config';
import * as alertFilterControlsPackage from '@kbn/alerts-ui-shared/src/alert_filter_controls/alert_filter_controls';
import { DetectionEnginePage } from './detection_engine';
import { TableId } from '@kbn/securitysolution-data-table';
import { useUpsellingMessage } from '../../../common/hooks/use_upselling';
import { SECURITY_FEATURE_ID } from '../../../../common/constants';

// Test will fail because we will to need to mock some core services to make the test work
// For now let's forget about SiemSearchBar and QueryBar
jest.mock('../../../common/components/search_bar', () => ({
  SiemSearchBar: () => null,
}));
jest.mock('../../../common/components/query_bar', () => ({
  QueryBar: () => null,
}));
jest.mock('../../../common/hooks/use_space_id', () => ({
  useSpaceId: () => 'default',
}));
jest.mock('@kbn/alerts-ui-shared/src/alert_filter_controls/alert_filter_controls');
jest.mock('../../components/alerts_table/alerts_grouping', () => ({
  GroupedAlertsTable: () => <span />,
}));
jest.mock('../../containers/detection_engine/lists/use_lists_config');
jest.mock('../../components/user_info');
jest.mock('../../../sourcerer/containers');
jest.mock('../../../common/components/link_to');
jest.mock('../../../common/containers/use_global_time', () => ({
  useGlobalTime: jest.fn().mockReturnValue({
    from: '2020-07-07T08:20:18.966Z',
    isInitializing: false,
    to: '2020-07-08T08:20:18.966Z',
    setQuery: jest.fn(),
  }),
}));
jest.mock('react-router-dom', () => {
  const originalModule = jest.requireActual('react-router-dom');

  return {
    ...originalModule,
    useParams: jest.fn(),
    useHistory: jest.fn(),
  };
});

const mockFilterManager = createFilterManagerMock();

const stubSecurityDataView = createStubDataView({
  spec: {
    id: 'security',
    title: 'security',
  },
});

const mockDataViewsService = {
  ...dataViewPluginMocks.createStartContract(),
  get: () => Promise.resolve(stubSecurityDataView),
  clearInstanceCache: () => Promise.resolve(),
};

const mockUseKibanaReturnValue = {
  services: {
    application: {
      navigateToUrl: jest.fn(),
      capabilities: {
        [SECURITY_FEATURE_ID]: { crud_alerts: true, read_alerts: true },
      },
    },
    dataViews: mockDataViewsService,
    cases: {
      ui: { getCasesContext: mockCasesContext },
    },
    timelines: { ...mockTimelines },
    data: {
      query: {
        filterManager: mockFilterManager,
      },
    },
    docLinks: {
      links: {
        [SECURITY_FEATURE_ID]: {
          privileges: 'link',
        },
      },
    },
    storage: {
      get: jest.fn(),
      set: jest.fn(),
    },
    triggersActionsUi: {
      alertsTableConfigurationRegistry: {},
      getAlertsStateTable: () => <></>,
    },
    sessionView: {
      getSessionView: jest.fn(() => <div />),
    },
    notifications: {
      toasts: {
        addWarning: jest.fn(),
        addError: jest.fn(),
        addSuccess: jest.fn(),
        addDanger: jest.fn(),
        remove: jest.fn(),
      },
    },
  },
};
jest.mock('../../../common/lib/kibana', () => {
  const original = jest.requireActual('../../../common/lib/kibana');

  return {
    ...original,
    useUiSetting$: jest.fn().mockReturnValue([]),
    useKibana: () => mockUseKibanaReturnValue,
    useToasts: jest.fn().mockReturnValue({
      addError: jest.fn(),
      addSuccess: jest.fn(),
      addWarning: jest.fn(),
      addInfo: jest.fn(),
      remove: jest.fn(),
    }),
  };
});

const dataViewId = 'security-solution-default';

const stateWithBuildingBlockAlertsEnabled: State = {
  ...mockGlobalState,
  dataTable: {
    ...mockGlobalState.dataTable,
    tableById: {
      ...mockGlobalState.dataTable.tableById,
      [TableId.test]: {
        ...mockGlobalState.dataTable.tableById[TableId.test],
        additionalFilters: {
          showOnlyThreatIndicatorAlerts: false,
          showBuildingBlockAlerts: true,
        },
      },
    },
  },
};

const stateWithThreatIndicatorsAlertEnabled: State = {
  ...mockGlobalState,
  dataTable: {
    ...mockGlobalState.dataTable,
    tableById: {
      ...mockGlobalState.dataTable.tableById,
      [TableId.test]: {
        ...mockGlobalState.dataTable.tableById[TableId.test],
        additionalFilters: {
          showOnlyThreatIndicatorAlerts: true,
          showBuildingBlockAlerts: false,
        },
      },
    },
  },
};

jest.mock('../../components/alerts_table/timeline_actions/use_add_bulk_to_timeline', () => ({
  useAddBulkToTimelineAction: jest.fn(() => {}),
}));

jest.mock('../../../common/components/visualization_actions/lens_embeddable');
jest.mock('../../../common/components/page/use_refetch_by_session');
jest.mock('../../../common/hooks/use_upselling');

describe('DetectionEnginePageComponent', () => {
  beforeAll(() => {
    (useListsConfig as jest.Mock).mockReturnValue({ loading: false, needsConfiguration: false });
    (useParams as jest.Mock).mockReturnValue({});
    (useUserData as jest.Mock).mockReturnValue([
      {
        loading: false,
        hasIndexRead: true,
        canUserREAD: true,
      },
    ]);
    (useSourcererDataView as jest.Mock).mockReturnValue({
      indicesExist: true,
      browserFields: mockBrowserFields,
      sourcererDataView: {
        fields: {},
        title: 'mock-*',
      },
    });
    jest
      .spyOn(alertFilterControlsPackage, 'AlertFilterControls')
      .mockImplementation(() => <span data-test-subj="filter-group__loading" />);
    (useUpsellingMessage as jest.Mock).mockReturnValue('Go for Platinum!');
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders correctly', async () => {
    const { getByTestId } = render(
      <TestProviders>
        <Router history={mockHistory}>
          <DetectionEnginePage />
        </Router>
      </TestProviders>
    );
    await waitFor(() => {
      expect(getByTestId('filter-group__loading')).toBeInTheDocument();
    });
  });

  it('renders the chart panels', async () => {
    const { getByTestId } = render(
      <TestProviders>
        <Router history={mockHistory}>
          <DetectionEnginePage />
        </Router>
      </TestProviders>
    );

    await waitFor(() => {
      expect(getByTestId('chartPanels')).toBeInTheDocument();
    });
  });

  it('should pass building block filter to the alert Page Controls', async () => {
    render(
      <TestProviders store={createMockStore(stateWithBuildingBlockAlertsEnabled)}>
        <Router history={mockHistory}>
          <DetectionEnginePage />
        </Router>
      </TestProviders>
    );

    await waitFor(() =>
      expect(jest.spyOn(alertFilterControlsPackage, 'AlertFilterControls')).toHaveBeenCalledWith(
        expect.objectContaining({
          filters: [
            {
              meta: {
                alias: null,
                negate: true,
                disabled: false,
                type: 'exists',
                key: 'kibana.alert.building_block_type',
                value: 'exists',
                index: dataViewId,
              },
              query: {
                exists: {
                  field: 'kibana.alert.building_block_type',
                },
              },
            },
          ],
        }),
        expect.anything()
      )
    );
  });

  it('should pass threat Indicator filter to the alert Page Controls', async () => {
    render(
      <TestProviders store={createMockStore(stateWithThreatIndicatorsAlertEnabled)}>
        <Router history={mockHistory}>
          <DetectionEnginePage />
        </Router>
      </TestProviders>
    );

    expect(jest.spyOn(alertFilterControlsPackage, 'AlertFilterControls')).toHaveBeenCalledWith(
      expect.objectContaining({
        filters: [
          {
            meta: {
              alias: null,
              negate: true,
              disabled: false,
              type: 'exists',
              key: 'kibana.alert.building_block_type',
              value: 'exists',
              index: dataViewId,
            },
            query: {
              exists: {
                field: 'kibana.alert.building_block_type',
              },
            },
          },
        ],
      }),
      expect.anything()
    );
  });
});
