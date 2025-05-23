/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import expect from '@kbn/expect';

import { FtrProviderContext } from '../ftr_provider_context';

export default function ({ getService, getPageObjects }: FtrProviderContext) {
  const esArchiver = getService('esArchiver');
  const { common, timePicker, discover } = getPageObjects(['common', 'timePicker', 'discover']);
  const kibanaServer = getService('kibanaServer');
  const security = getService('security');
  const fromTime = 'Sep 22, 2019 @ 20:31:44.000';
  const toTime = 'Sep 23, 2019 @ 03:31:44.000';

  describe('date_nanos', function () {
    before(async function () {
      await esArchiver.loadIfNeeded('src/platform/test/functional/fixtures/es_archiver/date_nanos');
      await kibanaServer.savedObjects.clean({ types: ['search', 'index-pattern'] });
      await kibanaServer.importExport.load(
        'src/platform/test/functional/fixtures/kbn_archiver/date_nanos'
      );
      await kibanaServer.uiSettings.replace({ defaultIndex: 'date-nanos' });
      await security.testUser.setRoles(['kibana_admin', 'kibana_date_nanos']);
      await common.navigateToApp('discover');
      await timePicker.setAbsoluteRange(fromTime, toTime);
    });

    after(async function unloadMakelogs() {
      await security.testUser.restoreDefaults();
      await esArchiver.unload('src/platform/test/functional/fixtures/es_archiver/date_nanos');
      await kibanaServer.savedObjects.clean({ types: ['search', 'index-pattern'] });
    });

    it('should show a timestamp with nanoseconds in the first result row', async function () {
      const time = await timePicker.getTimeConfig();
      expect(time.start).to.be(fromTime);
      expect(time.end).to.be(toTime);
      const rowData = await discover.getDocTableIndex(1);
      expect(rowData.startsWith('Sep 22, 2019 @ 23:50:13.253123345')).to.be.ok();
    });
  });
}
