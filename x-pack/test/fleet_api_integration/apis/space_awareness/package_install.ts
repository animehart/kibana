/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import expect from '@kbn/expect';
import { FtrProviderContext } from '../../../api_integration/ftr_provider_context';
import { skipIfNoDockerRegistry } from '../../helpers';
import { SpaceTestApiClient } from './api_helper';
import { cleanFleetIndices, createFleetAgent } from './helpers';

export default function (providerContext: FtrProviderContext) {
  const { getService } = providerContext;
  const supertest = getService('supertest');
  const esClient = getService('es');
  const kibanaServer = getService('kibanaServer');
  const spaces = getService('spaces');
  let TEST_SPACE_1: string;

  describe('package install', function () {
    skipIfNoDockerRegistry(providerContext);
    const apiClient = new SpaceTestApiClient(supertest);

    before(async () => {
      TEST_SPACE_1 = spaces.getDefaultTestSpace();
      await kibanaServer.savedObjects.cleanStandardList();
      await kibanaServer.savedObjects.cleanStandardList({
        space: TEST_SPACE_1,
      });
      await cleanFleetIndices(esClient);
      await spaces.createTestSpace(TEST_SPACE_1);
    });

    after(async () => {
      await kibanaServer.savedObjects.cleanStandardList();
      await kibanaServer.savedObjects.cleanStandardList({
        space: TEST_SPACE_1,
      });
      await cleanFleetIndices(esClient);
    });

    describe('kibana_assets', () => {
      describe('with package installed in default space', () => {
        before(async () => {
          await kibanaServer.savedObjects.cleanStandardList();
          await kibanaServer.savedObjects.cleanStandardList({
            space: TEST_SPACE_1,
          });
          await cleanFleetIndices(esClient);
          await apiClient.installPackage({
            pkgName: 'nginx',
            pkgVersion: '1.20.0',
            force: true, // To avoid package verification
          });
        });

        after(async () => {
          await kibanaServer.savedObjects.cleanStandardList();
          await kibanaServer.savedObjects.cleanStandardList({
            space: TEST_SPACE_1,
          });
          await cleanFleetIndices(esClient);
        });

        it('should not allow to install kibana assets for a non installed package', async () => {
          let err: Error | undefined;
          try {
            await apiClient.installPackageKibanaAssets({ pkgName: 'test', pkgVersion: '1.0.0' });
          } catch (_err) {
            err = _err;
          }
          expect(err).to.be.an(Error);
          expect(err?.message).to.match(/404 "Not Found"/);
        });

        it('should not allow to install kibana assets for a non installed package version', async () => {
          let err: Error | undefined;
          try {
            await apiClient.installPackageKibanaAssets({ pkgName: 'nginx', pkgVersion: '1.19.0' });
          } catch (_err) {
            err = _err;
          }
          expect(err).to.be.an(Error);
          expect(err?.message).to.match(/404 "Not Found"/);
        });

        it('should allow to install kibana assets in default space', async () => {
          await apiClient.installPackageKibanaAssets({ pkgName: 'nginx', pkgVersion: '1.20.0' });

          const res = await apiClient.getPackage({ pkgName: 'nginx', pkgVersion: '1.20.0' });
          if (!('installationInfo' in res.item)) {
            throw new Error('not installed');
          }

          expect(res.item.installationInfo?.installed_kibana_space_id).eql('default');
          expect(res.item.installationInfo?.additional_spaces_installed_kibana).eql(undefined);
        });

        it('should allow to install kibana assets in another space', async () => {
          await apiClient.installPackageKibanaAssets(
            { pkgName: 'nginx', pkgVersion: '1.20.0' },
            TEST_SPACE_1
          );

          const res = await apiClient.getPackage({ pkgName: 'nginx', pkgVersion: '1.20.0' });
          if (!('installationInfo' in res.item)) {
            throw new Error('not installed');
          }

          expect(res.item.installationInfo?.installed_kibana_space_id).eql('default');
          expect(
            Object.keys(res.item.installationInfo?.additional_spaces_installed_kibana ?? {})
          ).eql([TEST_SPACE_1]);

          const dashboard = res.item.installationInfo!.additional_spaces_installed_kibana?.[
            TEST_SPACE_1
          ]!.find((asset) => asset.originId === 'nginx-046212a0-a2a1-11e7-928f-5dbe6f6f5519');
          expect(dashboard).not.eql(undefined);
        });

        it('should not allow to delete kibana assets from default space', async () => {
          let err: Error | undefined;
          try {
            await apiClient.deletePackageKibanaAssets({ pkgName: 'nginx', pkgVersion: '1.20.0' });
          } catch (_err) {
            err = _err;
          }
          expect(err).to.be.an(Error);
          expect(err?.message).to.match(/400 "Bad Request"/);
        });

        it('should allow to delete kibana assets from test space', async () => {
          await apiClient.deletePackageKibanaAssets(
            { pkgName: 'nginx', pkgVersion: '1.20.0' },
            TEST_SPACE_1
          );

          const res = await apiClient.getPackage({ pkgName: 'nginx', pkgVersion: '1.20.0' });
          if (!('installationInfo' in res.item)) {
            throw new Error('not installed');
          }
          expect(
            Object.keys(res.item.installationInfo?.additional_spaces_installed_kibana ?? {})
          ).eql([]);
        });

        it('should allow to install kibana in another space from the default space', async () => {
          await apiClient.installPackageKibanaAssets({
            pkgName: 'nginx',
            pkgVersion: '1.20.0',
            spaceIds: [TEST_SPACE_1],
          });

          const res = await apiClient.getPackage({ pkgName: 'nginx', pkgVersion: '1.20.0' });
          if (!('installationInfo' in res.item)) {
            throw new Error('not installed');
          }

          expect(res.item.installationInfo?.installed_kibana_space_id).eql('default');
          expect(
            Object.keys(res.item.installationInfo?.additional_spaces_installed_kibana ?? {})
          ).eql([TEST_SPACE_1]);
        });
      });

      describe('with package installed in test space', () => {
        before(async () => {
          await kibanaServer.savedObjects.cleanStandardList();
          await kibanaServer.savedObjects.cleanStandardList({
            space: TEST_SPACE_1,
          });
          await cleanFleetIndices(esClient);
          await apiClient.installPackage(
            {
              pkgName: 'nginx',
              pkgVersion: '1.20.0',
              force: true, // To avoid package verification
            },
            TEST_SPACE_1
          );
        });

        after(async () => {
          await kibanaServer.savedObjects.cleanStandardList();
          await kibanaServer.savedObjects.cleanStandardList({
            space: TEST_SPACE_1,
          });
          await cleanFleetIndices(esClient);
        });

        it('should not allow to install kibana assets for a non installed package', async () => {
          let err: Error | undefined;
          try {
            await apiClient.installPackageKibanaAssets({ pkgName: 'test', pkgVersion: '1.0.0' });
          } catch (_err) {
            err = _err;
          }
          expect(err).to.be.an(Error);
          expect(err?.message).to.match(/404 "Not Found"/);
        });

        it('should not allow to install kibana assets for a non installed package version', async () => {
          let err: Error | undefined;
          try {
            await apiClient.installPackageKibanaAssets({ pkgName: 'nginx', pkgVersion: '1.19.0' });
          } catch (_err) {
            err = _err;
          }
          expect(err).to.be.an(Error);
          expect(err?.message).to.match(/404 "Not Found"/);
        });

        it('should allow to install kibana assets in test space', async () => {
          await apiClient.installPackageKibanaAssets(
            { pkgName: 'nginx', pkgVersion: '1.20.0' },
            TEST_SPACE_1
          );

          const res = await apiClient.getPackage({ pkgName: 'nginx', pkgVersion: '1.20.0' });
          if (!('installationInfo' in res.item)) {
            throw new Error('not installed');
          }

          expect(res.item.installationInfo?.installed_kibana_space_id).eql(TEST_SPACE_1);
          expect(res.item.installationInfo?.additional_spaces_installed_kibana).eql(undefined);
        });

        it('should allow to install kibana assets in default space', async () => {
          await apiClient.installPackageKibanaAssets({ pkgName: 'nginx', pkgVersion: '1.20.0' });

          const res = await apiClient.getPackage({ pkgName: 'nginx', pkgVersion: '1.20.0' });
          if (!('installationInfo' in res.item)) {
            throw new Error('not installed');
          }

          expect(res.item.installationInfo?.installed_kibana_space_id).eql(TEST_SPACE_1);
          expect(
            Object.keys(res.item.installationInfo?.additional_spaces_installed_kibana ?? {})
          ).eql(['default']);

          const dashboard =
            res.item.installationInfo!.additional_spaces_installed_kibana?.default!.find(
              (asset) => asset.originId === 'nginx-046212a0-a2a1-11e7-928f-5dbe6f6f5519'
            );
          expect(dashboard).not.eql(undefined);
        });
      });
    });

    describe('uninstall', () => {
      beforeEach(async () => {
        await apiClient.installPackage({
          pkgName: 'nginx',
          pkgVersion: '1.20.0',
          force: true, // To avoid package verification
        });
        const agentPolicyRes = await apiClient.createAgentPolicy();

        await apiClient.createPackagePolicy(undefined, {
          policy_ids: [agentPolicyRes.item.id],
          name: `test-nginx-${Date.now()}`,
          description: 'test',
          package: {
            name: 'nginx',
            version: '1.20.0',
          },
          inputs: {},
        });

        await createFleetAgent(esClient, agentPolicyRes.item.id);
      });

      it('should not allow to delete a package with active agents in the same space', async () => {
        let err: Error | undefined;
        try {
          await apiClient.uninstallPackage({
            pkgName: 'nginx',
            pkgVersion: '1.20.0',
            force: true, // To avoid package verification
          });
        } catch (_err) {
          err = _err;
        }
        expect(err).to.be.an(Error);
        expect(err?.message).to.match(/400 "Bad Request"/);
      });
      it('should not allow to delete a package with active agents in a different space', async () => {
        let err: Error | undefined;
        try {
          await apiClient.uninstallPackage(
            {
              pkgName: 'nginx',
              pkgVersion: '1.20.0',
              force: true, // To avoid package verification
            },
            TEST_SPACE_1
          );
        } catch (_err) {
          err = _err;
        }
        expect(err).to.be.an(Error);
        expect(err?.message).to.match(/400 "Bad Request"/);
      });
    });
  });
}
