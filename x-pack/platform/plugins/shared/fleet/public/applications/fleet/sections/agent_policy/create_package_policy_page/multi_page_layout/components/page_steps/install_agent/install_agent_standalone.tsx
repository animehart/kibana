/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState } from 'react';
import { FormattedMessage } from '@kbn/i18n-react';
import { EuiSteps, EuiSpacer } from '@elastic/eui';

import { getRootIntegrations } from '../../../../../../../../../../common/services';
import {
  AgentStandaloneBottomBar,
  StandaloneModeWarningCallout,
  NotObscuredByBottomBar,
} from '../..';

import { Error as FleetError } from '../../../../../../../components';
import {
  useKibanaVersion,
  useShowCompleteAgentInstructions,
} from '../../../../../../../../../hooks';
import {
  InstallStandaloneAgentStep,
  ConfigureStandaloneAgentStep,
} from '../../../../../../../../../components/agent_enrollment_flyout/steps';
import { StandaloneInstructions } from '../../../../../../../../../components/enrollment_instructions';

import { useFetchFullPolicy } from '../../../../../../../../../components/agent_enrollment_flyout/hooks';

import type { InstallAgentPageProps } from './types';

export const InstallElasticAgentStandalonePageStep: React.FC<InstallAgentPageProps> = (props) => {
  const { setIsManaged, agentPolicy, cancelUrl, onNext, cancelClickHandler } = props;

  const kibanaVersion = useKibanaVersion();
  const [commandCopied, setCommandCopied] = useState(false);
  const [policyCopied, setPolicyCopied] = useState(false);

  const { yaml, onCreateApiKey, isCreatingApiKey, apiKey, downloadYaml } =
    useFetchFullPolicy(agentPolicy);

  const { onChangeShowCompleteAgentInstructions, showCompleteAgentInstructions } =
    useShowCompleteAgentInstructions();

  if (!agentPolicy) {
    return (
      <FleetError
        title={
          <FormattedMessage
            id="xpack.fleet.createPackagePolicy.errorLoadingPackageTitle"
            defaultMessage="Error loading package information"
          />
        }
        error={'Agent policy not provided'}
      />
    );
  }

  const installManagedCommands = StandaloneInstructions({
    agentVersion: kibanaVersion,
    showCompleteAgentInstructions,
  });

  const steps = [
    ConfigureStandaloneAgentStep({
      selectedPolicyId: agentPolicy?.id,
      yaml,
      downloadYaml,
      apiKey,
      onCreateApiKey,
      isCreatingApiKey,
      isComplete: policyCopied,
      onCopy: () => setPolicyCopied(true),
    }),
    InstallStandaloneAgentStep({
      installCommand: installManagedCommands,
      isComplete: yaml && commandCopied,
      fullCopyButton: true,
      onCopy: () => setCommandCopied(true),
      rootIntegrations: getRootIntegrations(agentPolicy?.package_policies ?? []),
      onChangeShowCompleteAgentInstructions,
      showCompleteAgentInstructions,
    }),
  ];

  return (
    <>
      <StandaloneModeWarningCallout setIsManaged={setIsManaged} />
      <EuiSpacer size="xl" />
      <EuiSteps steps={steps} />
      {commandCopied && (
        <>
          <NotObscuredByBottomBar />
          <AgentStandaloneBottomBar
            cancelUrl={cancelUrl}
            onNext={onNext}
            cancelClickHandler={cancelClickHandler}
          />
        </>
      )}
    </>
  );
};
