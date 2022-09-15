/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import userEvent from '@testing-library/user-event';
import type { AuthenticatedUser } from '@kbn/security-plugin/common';
import { useCurrentUser } from '../../../../../common/lib/kibana';
import { securityMock } from '@kbn/security-plugin/public/mocks';
import { screen } from '@testing-library/react';
import { EndpointPolicyCreateExtension } from './endpoint_policy_create_extension';
import type { NewPackagePolicy } from '@kbn/fleet-plugin/common';
import { licenseService } from '../../../../../common/hooks/use_license';
import type { AppContextTestRender } from '../../../../../common/mock/endpoint';
import { createAppRootMockRenderer } from '../../../../../common/mock/endpoint';

jest.mock('../../../../../common/lib/kibana');
jest.mock('../../../../../common/hooks/use_license', () => {
  const licenseServiceInstance = {
    isPlatinumPlus: jest.fn(),
    isEnterprise: jest.fn(() => true),
  };
  return {
    licenseService: licenseServiceInstance,
    useLicense: () => {
      return licenseServiceInstance;
    },
  };
});

describe('Onboarding Component new section', () => {
  let render: () => ReturnType<AppContextTestRender['render']>;
  let renderResult: ReturnType<typeof render>;
  let mockedContext: AppContextTestRender;

  beforeEach(() => {
    mockedContext = createAppRootMockRenderer();
  });

  describe('When EndpointPolicyCreateExtension is mounted', () => {
    it('renders EndpointPolicyCreateExtension options correctly (Default to Endpoint)', async () => {
      renderResult = mockedContext.render(
        <EndpointPolicyCreateExtension
          newPolicy={{ id: 'someid' } as NewPackagePolicy}
          onChange={jest.fn()}
        />
      );
      expect(renderResult.queryByText('NGAV')).toBeVisible();
      expect(renderResult.queryByText('EDR Essential')).toBeVisible();
      expect(renderResult.queryByText('EDR Complete')).toBeVisible();
    });

    it('renders EndpointPolicyCreateExtension options correctly (set to Cloud)', async () => {
      renderResult = mockedContext.render(
        <EndpointPolicyCreateExtension
          newPolicy={{ id: 'someid' } as NewPackagePolicy}
          onChange={jest.fn()}
        />
      );
      userEvent.selectOptions(screen.getByTestId('selectIntegrationTypeId'), ['cloud']);
      expect(renderResult.getByText('Interactive only')).toBeVisible();
      expect(renderResult.getByText('All events')).toBeVisible();
      expect(renderResult.getByText('Prevent Malware')).toBeVisible();
      expect(renderResult.queryByText('Prevent Malicious Behaviour')).toBeNull();
    });

    // it('Click Test', async () => {
    //     renderResult = mockedContext.render(
    //       <EndpointPolicyCreateExtension
    //         newPolicy={{ id: 'someid' } as NewPackagePolicy}
    //         onChange={jest.fn()}
    //       />
    //     );
    //     userEvent.selectOptions(screen.getByTestId('selectIntegrationTypeId'), ['cloud']);
    //     expect(renderResult.getByText('Interactive only')).toBeVisible();
    //     expect(renderResult.getByText('All events')).toBeVisible();
    //     renderResult.getByText('All events').click();
    //     expect(renderResult.getByText('Prevent Malicious Behaviourz')).toBeVisible();
    //   });

    it('renders EndpointPolicyCreateExtension options correctly (set to Cloud + Platinum license)', async () => {
      const licenseServiceMock = licenseService as jest.Mocked<typeof licenseService>;

      const authenticatedUser: AuthenticatedUser = securityMock.createMockAuthenticatedUser({
        roles: ['superuser'],
      });

      (useCurrentUser as jest.Mock).mockReturnValue(authenticatedUser);

      licenseServiceMock.isPlatinumPlus.mockReturnValue(true);

      renderResult = mockedContext.render(
        <EndpointPolicyCreateExtension
          newPolicy={{ id: 'someid' } as NewPackagePolicy}
          onChange={jest.fn()}
        />
      );
      userEvent.selectOptions(screen.getByTestId('selectIntegrationTypeId'), ['cloud']);
      expect(renderResult.getByText('Interactive only')).toBeVisible();
      expect(renderResult.getByText('All events')).toBeVisible();
      expect(renderResult.getByText('Prevent Malware')).toBeVisible();
      expect(renderResult.getByText('Prevent Malicious Behaviour')).toBeVisible();
    });
  });
});
