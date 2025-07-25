/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo } from 'react';
import {
  EuiHorizontalRule,
  EuiFlexGroup,
  EuiFlexItem,
  EuiEmptyPrompt,
  EuiText,
} from '@elastic/eui';
import { FormattedMessage } from '@kbn/i18n-react';

import {
  getNormalizedInputs,
  isIntegrationPolicyTemplate,
  getRegistryStreamWithDataStreamForInputType,
} from '../../../../../../../../common/services';
import { isInputAllowedForDeploymentMode } from '../../../../../../../../common/services/agentless_policy_helper';

import type { PackageInfo, NewPackagePolicy, NewPackagePolicyInput } from '../../../../../types';
import { Loading } from '../../../../../components';
import { doesPackageHaveIntegrations } from '../../../../../services';

import type { PackagePolicyValidationResults } from '../../services';

import { PackagePolicyInputPanel } from './components';

export const StepConfigurePackagePolicy: React.FunctionComponent<{
  packageInfo: PackageInfo;
  showOnlyIntegration?: string;
  packagePolicy: NewPackagePolicy;
  updatePackagePolicy: (fields: Partial<NewPackagePolicy>) => void;
  validationResults: PackagePolicyValidationResults | undefined;
  submitAttempted: boolean;
  noTopRule?: boolean;
  isEditPage?: boolean;
  isAgentlessSelected?: boolean;
}> = ({
  packageInfo,
  showOnlyIntegration,
  packagePolicy,
  updatePackagePolicy,
  validationResults,
  submitAttempted,
  noTopRule = false,
  isEditPage = false,
  isAgentlessSelected = false,
}) => {
  const hasIntegrations = useMemo(() => doesPackageHaveIntegrations(packageInfo), [packageInfo]);
  const packagePolicyTemplates = useMemo(
    () =>
      showOnlyIntegration
        ? (packageInfo.policy_templates || []).filter(
            (policyTemplate) => policyTemplate.name === showOnlyIntegration
          )
        : packageInfo.policy_templates || [],
    [packageInfo.policy_templates, showOnlyIntegration]
  );
  // Configure inputs (and their streams)
  const renderConfigureInputs = () =>
    packagePolicyTemplates.length ? (
      <>
        {!noTopRule && <EuiHorizontalRule margin="m" />}
        <EuiFlexGroup direction="column" gutterSize="none">
          {packagePolicyTemplates.map((policyTemplate) => {
            const inputs = getNormalizedInputs(policyTemplate);
            const packagePolicyInputs = packagePolicy.inputs;
            return inputs.map((packageInput) => {
              const packagePolicyInput = packagePolicyInputs.find(
                (input) =>
                  input.type === packageInput.type &&
                  (hasIntegrations ? input.policy_template === policyTemplate.name : true)
              );
              const packageInputStreams = getRegistryStreamWithDataStreamForInputType(
                packageInput.type,
                packageInfo,
                hasIntegrations && isIntegrationPolicyTemplate(policyTemplate)
                  ? policyTemplate.data_streams
                  : []
              );

              const updatePackagePolicyInput = (updatedInput: Partial<NewPackagePolicyInput>) => {
                const indexOfUpdatedInput = packagePolicyInputs.findIndex(
                  (input) =>
                    input.type === packageInput.type &&
                    (hasIntegrations ? input.policy_template === policyTemplate.name : true)
                );
                const newInputs = [...packagePolicyInputs];
                newInputs[indexOfUpdatedInput] = {
                  ...newInputs[indexOfUpdatedInput],
                  ...updatedInput,
                };
                updatePackagePolicy({
                  inputs: newInputs,
                });
              };

              const isInputAvailable =
                packagePolicyInput &&
                isInputAllowedForDeploymentMode(
                  packagePolicyInput,
                  isAgentlessSelected && packagePolicy.supports_agentless ? 'agentless' : 'default',
                  packageInfo
                );

              return isInputAvailable ? (
                <EuiFlexItem key={packageInput.type}>
                  <PackagePolicyInputPanel
                    packageInput={packageInput}
                    packageInfo={packageInfo}
                    packageInputStreams={packageInputStreams}
                    packagePolicyInput={packagePolicyInput}
                    updatePackagePolicyInput={updatePackagePolicyInput}
                    inputValidationResults={
                      validationResults?.inputs?.[
                        hasIntegrations
                          ? `${policyTemplate.name}-${packagePolicyInput.type}`
                          : packagePolicyInput.type
                      ] ?? {}
                    }
                    forceShowErrors={submitAttempted}
                    isEditPage={isEditPage}
                  />
                  <EuiHorizontalRule margin="m" />
                </EuiFlexItem>
              ) : null;
            });
          })}
        </EuiFlexGroup>
      </>
    ) : (
      <EuiEmptyPrompt
        iconType="checkInCircleFilled"
        iconColor="success"
        body={
          <EuiText>
            <p>
              <FormattedMessage
                id="xpack.fleet.createPackagePolicy.stepConfigure.noPolicyOptionsMessage"
                defaultMessage="Nothing to configure"
              />
            </p>
          </EuiText>
        }
      />
    );

  return validationResults ? renderConfigureInputs() : <Loading />;
};
