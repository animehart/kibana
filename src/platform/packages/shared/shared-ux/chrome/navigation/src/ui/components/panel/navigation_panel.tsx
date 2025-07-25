/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import {
  EuiFocusTrap,
  EuiOutsideClickDetector,
  EuiPanel,
  EuiWindowEvent,
  keys,
} from '@elastic/eui';
import React, { useCallback, type FC } from 'react';
import classNames from 'classnames';

import type { PanelSelectedNode } from '@kbn/core-chrome-browser';
import { usePanel } from './context';
import { navPanelStyles, panelWrapperStyles } from './styles';

const getTestSubj = (selectedNode: PanelSelectedNode | null): string | undefined => {
  if (!selectedNode) return;

  const deeplinkId = selectedNode.deepLink?.id;
  return classNames(`sideNavPanel`, {
    [`sideNavPanel-id-${selectedNode.id}`]: selectedNode.id,
    [`sideNavPanel-deepLinkId-${deeplinkId}`]: !!deeplinkId,
  });
};

export const NavigationPanel: FC = () => {
  const { isOpen, close, getContent, selectedNode, selectedNodeEl } = usePanel();

  // ESC key closes PanelNav
  const onKeyDown = useCallback(
    (ev: KeyboardEvent) => {
      if (ev.key === keys.ESCAPE) {
        close();
      }
    },
    [close]
  );

  const onOutsideClick = useCallback(
    ({ target }: Event) => {
      if (!target) {
        close();
        return;
      }

      let doClose = true;

      // Do not close if clicking on the button (or child of the button) of the currently selected node,
      // because we must defer to allowing the button's click handler to manage toggling.
      if (selectedNodeEl && selectedNodeEl.current?.contains(target as Node)) {
        doClose = false;
      }

      if (doClose) {
        close();
      }
    },
    [close, selectedNodeEl]
  );

  if (!isOpen) {
    return null;
  }

  const panelClasses = classNames('sideNavPanel', 'eui-yScroll');

  return (
    <>
      <EuiWindowEvent event="keydown" handler={onKeyDown} />
      <div css={panelWrapperStyles}>
        <EuiFocusTrap autoFocus style={{ height: '100%' }}>
          <EuiOutsideClickDetector onOutsideClick={onOutsideClick}>
            <EuiPanel
              className={panelClasses}
              css={navPanelStyles}
              hasShadow
              borderRadius="none"
              paddingSize="none"
              data-test-subj={getTestSubj(selectedNode)}
            >
              {getContent()}
            </EuiPanel>
          </EuiOutsideClickDetector>
        </EuiFocusTrap>
      </div>
    </>
  );
};
