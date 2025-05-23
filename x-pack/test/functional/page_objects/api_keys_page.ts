/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { FtrProviderContext } from '../ftr_provider_context';

export function ApiKeysPageProvider({ getService }: FtrProviderContext) {
  const testSubjects = getService('testSubjects');
  const find = getService('find');
  const monacoEditor = getService('monacoEditor');

  return {
    async noAPIKeysHeading() {
      return await testSubjects.getVisibleText('noApiKeysHeader');
    },

    async getApiKeyAdminDesc() {
      return await testSubjects.getVisibleText('apiKeyAdminDescriptionCallOut');
    },

    async getGoToConsoleButton() {
      return await testSubjects.find('goToConsoleButton');
    },

    async apiKeysPermissionDeniedMessage() {
      return await testSubjects.getVisibleText('apiKeysPermissionDeniedMessage');
    },

    async clickOnPromptCreateApiKey() {
      return await testSubjects.click('apiKeysCreatePromptButton');
    },

    async clickOnTableCreateApiKey() {
      return await testSubjects.click('apiKeysCreateTableButton');
    },

    async setApiKeyName(apiKeyName: string) {
      return await testSubjects.setValue('apiKeyNameInput', apiKeyName);
    },

    async getApiKeyName() {
      return await testSubjects.find('apiKeyNameInput');
    },

    async isApiKeyNamePresent() {
      return await testSubjects.exists('apiKeyNameInput');
    },

    async setApiKeyCustomExpiration(expirationTime: string) {
      return await testSubjects.setValue('apiKeyCustomExpirationInput', expirationTime);
    },

    async toggleCustomExpiration() {
      return await testSubjects.click('apiKeyCustomExpirationSwitch');
    },

    async clickSubmitButtonOnApiKeyFlyout() {
      return await testSubjects.click('formFlyoutSubmitButton');
    },

    async waitForSubmitButtonOnApiKeyFlyoutEnabled() {
      return testSubjects.waitForEnabled('formFlyoutSubmitButton', 10000);
    },

    async clickCancelButtonOnApiKeyFlyout() {
      return await testSubjects.click('formFlyoutCancelButton');
    },

    async isApiKeyModalExists() {
      return await find.existsByCssSelector('.euiFlyoutHeader');
    },

    async getNewApiKeyCreation() {
      const euiCallOutHeader = await find.byCssSelector('.euiCallOutHeader__title');
      return euiCallOutHeader.getVisibleText();
    },

    async isPromptPage() {
      return await testSubjects.exists('apiKeysCreatePromptButton');
    },

    async getApiKeysFirstPromptTitle() {
      const titlePromptElem = await find.byCssSelector('.euiEmptyPrompt .euiTitle');
      return await titlePromptElem.getVisibleText();
    },

    async deleteApiKeyByName(apiKeyName: string) {
      await testSubjects.click(`apiKeysTableDeleteAction-${apiKeyName}`);
      await testSubjects.click('confirmModalConfirmButton');
      await testSubjects.waitForDeleted(`apiKeyRowName-${apiKeyName}`);
    },

    async deleteAllApiKeyOneByOne() {
      const hasApiKeysToDelete = await testSubjects.exists('*apiKeysTableDeleteAction');
      if (hasApiKeysToDelete) {
        const apiKeysToDelete = await testSubjects.findAll('*apiKeysTableDeleteAction');
        for (const element of apiKeysToDelete) {
          await element.click();
          await testSubjects.click('confirmModalConfirmButton');
        }
      }
    },

    async bulkDeleteApiKeys() {
      const hasApiKeysToDelete = await testSubjects.exists('checkboxSelectAll', {
        allowHidden: true,
      });
      if (hasApiKeysToDelete) {
        await testSubjects.click('checkboxSelectAll');
        await testSubjects.click('bulkInvalidateActionButton');
        await testSubjects.click('confirmModalConfirmButton');
      }
    },

    async clickExistingApiKeyToOpenFlyout(apiKeyName: string) {
      await testSubjects.click(`apiKeyRowName-${apiKeyName}`);
    },

    async ensureApiKeyExists(apiKeyName: string) {
      await testSubjects.existOrFail(`apiKeyRowName-${apiKeyName}`);
    },

    async doesApiKeyExist(apiKeyName: string) {
      return await testSubjects.exists(`apiKeyRowName-${apiKeyName}`);
    },

    async getMetadataSwitch() {
      return await testSubjects.find('apiKeysMetadataSwitch');
    },

    async getCodeEditorValueByIndex(index: number) {
      return await monacoEditor.getCodeEditorValue(index);
    },

    async setCodeEditorValueByIndex(index: number, data: string) {
      await monacoEditor.setCodeEditorValue(data, index);
    },

    async getRestrictPrivilegesSwitch() {
      return await testSubjects.find('apiKeysRoleDescriptorsSwitch');
    },

    async getFlyoutTitleText() {
      const header = await find.byClassName('euiFlyoutHeader');
      return header.getVisibleText();
    },

    async getFlyoutApiKeyStatus() {
      const apiKeyStatusField = await testSubjects.find('apiKeyStatus');
      return apiKeyStatusField.getVisibleText();
    },

    async getApiKeyUpdateSuccessToast() {
      const toast = await testSubjects.find('updateApiKeySuccessToast');
      return toast.getVisibleText();
    },

    async clickExpiryFilters(type: 'active' | 'expired') {
      const button = await testSubjects.find(
        type === 'active' ? 'activeFilterButton' : 'expiredFilterButton'
      );
      return button.click();
    },

    async clickTypeFilters(type: 'personal' | 'managed' | 'cross_cluster') {
      const buttonMap = {
        personal: 'personalFilterButton',
        managed: 'managedFilterButton',
        cross_cluster: 'crossClusterFilterButton',
      };

      const button = await testSubjects.find(buttonMap[type]);
      return button.click();
    },

    async clickUserNameDropdown() {
      const button = await testSubjects.find('ownerFilterButton');
      return button.click();
    },

    async setSearchBarValue(query: string) {
      const searchBar = await testSubjects.find('apiKeysSearchBar');
      await searchBar.clearValue();
      return searchBar.type(query);
    },
  };
}
