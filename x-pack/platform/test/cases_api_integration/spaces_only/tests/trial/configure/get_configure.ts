/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type http from 'http';
import expect from '@kbn/expect';
import type { ConnectorTypes } from '@kbn/cases-plugin/common/types/domain';
import { ObjectRemover as ActionsRemover } from '../../../../../alerting_api_integration/common/lib';
import type { FtrProviderContext } from '../../../../common/ftr_provider_context';

import {
  createConfiguration,
  getConfiguration,
  getConfigurationRequest,
  removeServerGeneratedPropertiesFromSavedObject,
  getConfigurationOutput,
  getAuthWithSuperUser,
  getServiceNowConnector,
  createConnector,
  getServiceNowSimulationServer,
} from '../../../../common/lib/api';
import { nullUser } from '../../../../common/lib/mock';

export default ({ getService }: FtrProviderContext): void => {
  const supertest = getService('supertest');
  const supertestWithoutAuth = getService('supertestWithoutAuth');
  const actionsRemover = new ActionsRemover(supertest);
  const authSpace1 = getAuthWithSuperUser();

  describe('get_configure', () => {
    let serviceNowSimulatorURL: string = '';
    let serviceNowServer: http.Server;

    before(async () => {
      const { server, url } = await getServiceNowSimulationServer();
      serviceNowServer = server;
      serviceNowSimulatorURL = url;
    });

    afterEach(async () => {
      await actionsRemover.removeAll();
    });

    after(async () => {
      serviceNowServer.close();
    });

    it('should return a configuration with a mapping from space1', async () => {
      const connector = await createConnector({
        supertest: supertestWithoutAuth,
        req: {
          ...getServiceNowConnector(),
          config: { apiUrl: serviceNowSimulatorURL },
        },
        auth: authSpace1,
      });
      actionsRemover.add('space1', connector.id, 'connector', 'actions');

      await createConfiguration(
        supertestWithoutAuth,
        getConfigurationRequest({
          id: connector.id,
          name: connector.name,
          type: connector.connector_type_id as ConnectorTypes,
        }),
        200,
        authSpace1
      );

      const configuration = await getConfiguration({ supertest, auth: authSpace1 });

      const data = removeServerGeneratedPropertiesFromSavedObject(configuration[0]);
      expect(data).to.eql(
        getConfigurationOutput(false, {
          mappings: [
            {
              action_type: 'overwrite',
              source: 'title',
              target: 'short_description',
            },
            {
              action_type: 'overwrite',
              source: 'description',
              target: 'description',
            },
            {
              action_type: 'append',
              source: 'comments',
              target: 'work_notes',
            },
          ],
          connector: {
            id: connector.id,
            name: connector.name,
            type: connector.connector_type_id,
            fields: null,
          },
          created_by: nullUser,
        })
      );
    });

    it('should not return a configuration with a mapping from a different space', async () => {
      const connector = await createConnector({
        supertest: supertestWithoutAuth,
        req: {
          ...getServiceNowConnector(),
          config: { apiUrl: serviceNowSimulatorURL },
        },
        auth: authSpace1,
      });
      actionsRemover.add('space1', connector.id, 'connector', 'actions');

      await createConfiguration(
        supertest,
        getConfigurationRequest({
          id: connector.id,
          name: connector.name,
          type: connector.connector_type_id as ConnectorTypes,
        }),
        200,
        authSpace1
      );

      const configuration = await getConfiguration({
        supertest,
        auth: getAuthWithSuperUser('space2'),
      });

      expect(configuration).to.eql([]);
    });
  });
};
