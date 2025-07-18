/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useCallback, useEffect, useState, useMemo, useRef } from 'react';
import { i18n } from '@kbn/i18n';
import {
  LanguageDocumentationPopover,
  LanguageDocumentationPopoverContent,
} from '@kbn/language-documentation';
import { css } from '@emotion/react';
import {
  EuiButtonIcon,
  EuiButtonEmpty,
  EuiFormLabel,
  EuiFlexGroup,
  EuiFlexItem,
  EuiIcon,
  EuiLink,
  EuiPopover,
  EuiText,
  EuiToolTip,
  EuiSpacer,
  useEuiTheme,
  type UseEuiTheme,
} from '@elastic/eui';
import useUnmount from 'react-use/lib/useUnmount';
import { monaco } from '@kbn/monaco';
import { CodeEditor, CodeEditorProps } from '@kbn/code-editor';
import { UI_SETTINGS } from '@kbn/data-plugin/public';
import { useDebounceWithOptions } from '../../../../../../shared_components';
import { ParamEditorProps } from '../..';
import { getManagedColumnsFrom } from '../../../layer_helpers';
import { ErrorWrapper, runASTValidation, tryToParse } from '../validation';
import {
  LensMathSuggestions,
  SUGGESTION_TYPE,
  suggest,
  getSuggestion,
  getSignatureHelp,
  getHover,
  getTokenInfo,
  offsetToRowColumn,
  monacoPositionToOffset,
  createEditOperation,
  MARKER,
} from './math_completion';
import { LANGUAGE_ID } from './math_tokenization';

import { FormulaIndexPatternColumn } from '../formula';
import { insertOrReplaceFormulaColumn } from '../parse';
import { filterByVisibleOperation } from '../util';
import { getColumnTimeShiftWarnings, getDateHistogramInterval } from '../../../../time_shift_utils';
import { getDocumentationSections } from './formula_help';
import { nonNullable } from '../../../../../../utils';

function tableHasData(
  activeData: ParamEditorProps<FormulaIndexPatternColumn>['activeData'],
  layerId: string,
  columnId: string
) {
  const table = activeData?.[layerId];
  if (!table || table.rows.length === 0) {
    return false;
  }
  return table.rows.some((row) => row[columnId] != null);
}

export const WrappedFormulaEditor = ({
  activeData,
  ...rest
}: ParamEditorProps<FormulaIndexPatternColumn>) => {
  const dateHistogramInterval = getDateHistogramInterval(
    rest.data.datatableUtilities,
    rest.layer,
    rest.indexPattern,
    activeData,
    rest.layerId
  );
  return (
    <MemoizedFormulaEditor
      {...rest}
      dateHistogramInterval={dateHistogramInterval}
      hasData={tableHasData(activeData, rest.layerId, rest.columnId)}
    />
  );
};

const MemoizedFormulaEditor = React.memo(FormulaEditor);

const namedArgumentsTypes = new Set(['kql', 'lucene', 'shift', 'reducedTimeRange']);

export function FormulaEditor({
  layer,
  paramEditorUpdater,
  currentColumn,
  columnId,
  indexPattern,
  operationDefinitionMap,
  unifiedSearch,
  dataViews,
  toggleFullscreen,
  isFullscreen,
  dateHistogramInterval,
  hasData,
  dateRange,
  uiSettings,
  data,
}: Omit<ParamEditorProps<FormulaIndexPatternColumn>, 'activeData'> & {
  dateHistogramInterval: ReturnType<typeof getDateHistogramInterval>;
  hasData: boolean;
}) {
  const [text, setText] = useState(currentColumn.params.formula);
  const [warnings, setWarnings] = useState<
    Array<{ severity: monaco.MarkerSeverity; message: string }>
  >([]);
  const [isHelpOpen, setIsHelpOpen] = useState<boolean>(isFullscreen);
  const [isWarningOpen, setIsWarningOpen] = useState<boolean>(false);
  const [isWordWrapped, toggleWordWrap] = useState<boolean>(true);
  const editorModel = React.useRef<monaco.editor.ITextModel>();
  const overflowDiv1 = React.useRef<HTMLElement>();
  const disposables = React.useRef<monaco.IDisposable[]>([]);
  const editor1 = React.useRef<monaco.editor.IStandaloneCodeEditor>();

  const euiThemeContext = useEuiTheme();
  const { euiTheme } = euiThemeContext;

  const visibleOperationsMap = useMemo(
    () => filterByVisibleOperation(operationDefinitionMap),
    [operationDefinitionMap]
  );

  const documentationSections = useMemo(
    () =>
      getDocumentationSections({
        indexPattern,
        operationDefinitionMap: visibleOperationsMap,
      }),
    [indexPattern, visibleOperationsMap]
  );

  const baseInterval =
    'interval' in dateHistogramInterval
      ? dateHistogramInterval.interval?.asMilliseconds()
      : undefined;
  const baseIntervalRef = useRef(baseInterval);
  baseIntervalRef.current = baseInterval;

  // The Monaco editor needs to have the overflowDiv in the first render. Using an effect
  // requires a second render to work, so we are using an if statement to guarantee it happens
  // on first render
  if (!overflowDiv1?.current) {
    const node1 = (overflowDiv1.current = document.createElement('div'));
    node1.setAttribute('data-test-subj', 'lnsFormulaWidget');
    // Monaco CSS is targeted on the monaco-editor class
    node1.classList.add('lnsFormulaOverflow', 'monaco-editor');
    document.body.appendChild(node1);
  }

  // Clean up the monaco editor and DOM on unmount
  useEffect(() => {
    const model = editorModel;
    const allDisposables = disposables;
    const editor1ref = editor1;
    return () => {
      model.current?.dispose();
      overflowDiv1.current?.parentNode?.removeChild(overflowDiv1.current);
      editor1ref.current?.dispose();
      allDisposables.current?.forEach((d) => d.dispose());
    };
  }, []);

  useUnmount(() => {
    // If the text is not synced, update the column.
    if (text !== currentColumn.params.formula) {
      paramEditorUpdater(
        (prevLayer) =>
          insertOrReplaceFormulaColumn(
            columnId,
            {
              ...currentColumn,
              params: {
                ...currentColumn.params,
                formula: text || '',
              },
            },
            prevLayer,
            {
              indexPattern,
              operations: operationDefinitionMap,
              dateRange,
            }
          ).layer
      );
    }
  });

  useDebounceWithOptions(
    () => {
      if (!editorModel.current) return;

      if (!text) {
        setWarnings([]);
        monaco.editor.setModelMarkers(editorModel.current, 'LENS', []);
        if (currentColumn.params.formula) {
          // Only submit if valid
          paramEditorUpdater(
            insertOrReplaceFormulaColumn(
              columnId,
              {
                ...currentColumn,
                params: {
                  ...currentColumn.params,
                  formula: text || '',
                },
              },
              layer,
              {
                indexPattern,
                operations: operationDefinitionMap,
                dateRange,
              }
            ).layer
          );
        }

        return;
      }

      let errors: ErrorWrapper[] = [];

      const parseResponse = tryToParse(text, visibleOperationsMap);
      if ('error' in parseResponse) {
        errors = [parseResponse.error];
      } else {
        const validationErrors = runASTValidation(
          parseResponse.root,
          layer,
          indexPattern,
          visibleOperationsMap,
          currentColumn,
          dateRange
        );
        if (validationErrors.length) {
          errors = validationErrors;
        }
      }

      if (errors.length) {
        // Replace the previous error with the new one
        const previousFormulaWasBroken = currentColumn.params.isFormulaBroken;
        // If the user is changing a previous formula and there are currently no result
        // show the most up-to-date state with the error message.
        const previousFormulaWasOkButNoData = !currentColumn.params.isFormulaBroken && !hasData;
        if (previousFormulaWasBroken || previousFormulaWasOkButNoData) {
          // If the formula is already broken, show the latest error message in the workspace
          if (currentColumn.params.formula !== text) {
            paramEditorUpdater(
              insertOrReplaceFormulaColumn(
                columnId,
                {
                  ...currentColumn,
                  params: {
                    ...currentColumn.params,
                    formula: text || '',
                  },
                },
                layer,
                {
                  indexPattern,
                  operations: operationDefinitionMap,
                  dateRange,
                }
              ).layer
            );
          }
        }

        const markers = errors.flatMap((innerError) => {
          if (innerError.locations.length) {
            return innerError.locations.map((location) => {
              const startPosition = offsetToRowColumn(text, location.min);
              const endPosition = offsetToRowColumn(text, location.max);
              return {
                message: innerError.message,
                startColumn: startPosition.column + 1,
                startLineNumber: startPosition.lineNumber,
                endColumn: endPosition.column + 1,
                endLineNumber: endPosition.lineNumber,
                severity:
                  innerError.severity === 'warning'
                    ? monaco.MarkerSeverity.Warning
                    : monaco.MarkerSeverity.Error,
              };
            });
          } else {
            // Parse errors return no location info
            const startPosition = offsetToRowColumn(text, 0);
            const endPosition = offsetToRowColumn(text, text.length - 1);
            return [
              {
                message: innerError.message,
                startColumn: startPosition.column + 1,
                startLineNumber: startPosition.lineNumber,
                endColumn: endPosition.column + 1,
                endLineNumber: endPosition.lineNumber,
                severity:
                  innerError.severity === 'warning'
                    ? monaco.MarkerSeverity.Warning
                    : monaco.MarkerSeverity.Error,
              },
            ];
          }
        });

        monaco.editor.setModelMarkers(editorModel.current, 'LENS', markers);
        setWarnings(markers.map(({ severity, message }) => ({ severity, message })));
      } else {
        monaco.editor.setModelMarkers(editorModel.current, 'LENS', []);

        // Only submit if valid
        const {
          layer: newLayer,
          meta: { locations },
        } = insertOrReplaceFormulaColumn(
          columnId,
          {
            ...currentColumn,
            params: {
              ...currentColumn.params,
              formula: text || '',
            },
          },
          layer,
          {
            indexPattern,
            operations: operationDefinitionMap,
            dateRange,
          }
        );

        paramEditorUpdater(newLayer);

        const managedColumns = getManagedColumnsFrom(columnId, newLayer.columns);
        const markers: monaco.editor.IMarkerData[] = managedColumns
          .flatMap(([id, column]) => {
            const newWarnings: monaco.editor.IMarkerData[] = [];
            if (locations[id]) {
              const def = visibleOperationsMap[column.operationType];
              if (def.getErrorMessage) {
                const messages = def.getErrorMessage(
                  newLayer,
                  id,
                  indexPattern,
                  dateRange,
                  visibleOperationsMap,
                  uiSettings.get(UI_SETTINGS.HISTOGRAM_BAR_TARGET)
                );
                if (messages.length) {
                  const startPosition = offsetToRowColumn(text, locations[id].min);
                  const endPosition = offsetToRowColumn(text, locations[id].max);
                  newWarnings.push({
                    message: messages.map((e) => e.message).join(', '),
                    startColumn: startPosition.column + 1,
                    startLineNumber: startPosition.lineNumber,
                    endColumn: endPosition.column + 1,
                    endLineNumber: endPosition.lineNumber,
                    severity: monaco.MarkerSeverity.Warning,
                  });
                }
              }
              if (def.shiftable && column.timeShift) {
                const startPosition = offsetToRowColumn(text, locations[id].min);
                const endPosition = offsetToRowColumn(text, locations[id].max);
                newWarnings.push(
                  ...getColumnTimeShiftWarnings(dateHistogramInterval, column.timeShift).map(
                    (message) => ({
                      message,
                      startColumn: startPosition.column + 1,
                      startLineNumber: startPosition.lineNumber,
                      endColumn: endPosition.column + 1,
                      endLineNumber: endPosition.lineNumber,
                      severity: monaco.MarkerSeverity.Warning,
                    })
                  )
                );
              }
            }
            return newWarnings;
          })
          .filter(nonNullable);
        setWarnings(markers.map(({ severity, message }) => ({ severity, message })));
        monaco.editor.setModelMarkers(editorModel.current, 'LENS', markers);
      }
    },
    // Make it validate on flyout open in case of a broken formula left over
    // from a previous edit
    { skipFirstRender: false },
    256,
    [text, currentColumn.filter]
  );

  const errorCount = warnings.filter(
    (marker) => marker.severity === monaco.MarkerSeverity.Error
  ).length;
  const warningCount = warnings.filter(
    (marker) => marker.severity === monaco.MarkerSeverity.Warning
  ).length;

  /**
   * The way that Monaco requests autocompletion is not intuitive, but the way we use it
   * we fetch new suggestions in these scenarios:
   *
   * - If the user types one of the trigger characters, suggestions are always fetched
   * - When the user selects the kql= suggestion, we tell Monaco to trigger new suggestions after
   * - When the user types the first character into an empty text box, Monaco requests suggestions
   *
   * Monaco also triggers suggestions automatically when there are no suggestions being displayed
   * and the user types a non-whitespace character.
   *
   * While suggestions are being displayed, Monaco uses an in-memory cache of the last known suggestions.
   */
  const provideCompletionItems = useCallback(
    async (
      model: monaco.editor.ITextModel,
      position: monaco.Position,
      context: monaco.languages.CompletionContext
    ) => {
      const innerText = model.getValue();
      let aSuggestions: LensMathSuggestions = {
        list: [],
        type: SUGGESTION_TYPE.FIELD,
      };
      const offset = monacoPositionToOffset(innerText, position);

      if (context.triggerCharacter === '(') {
        // Monaco usually inserts the end quote and reports the position is after the end quote
        if (innerText.slice(offset - 1, offset + 1) === '()') {
          position = position.delta(0, -1);
        }
        const wordUntil = model.getWordAtPosition(position.delta(0, -3));
        if (wordUntil) {
          // Retrieve suggestions for subexpressions
          aSuggestions = await suggest({
            expression: innerText,
            zeroIndexedOffset: offset,
            context,
            indexPattern,
            operationDefinitionMap: visibleOperationsMap,
            unifiedSearch,
            dataViews,
            dateHistogramInterval: baseIntervalRef.current,
            timefilter: data.query.timefilter.timefilter,
          });
        }
      } else {
        aSuggestions = await suggest({
          expression: innerText,
          zeroIndexedOffset: offset,
          context,
          indexPattern,
          operationDefinitionMap: visibleOperationsMap,
          unifiedSearch,
          dataViews,
          dateHistogramInterval: baseIntervalRef.current,
          timefilter: data.query.timefilter.timefilter,
        });
      }

      return {
        suggestions: aSuggestions.list.map((s) =>
          getSuggestion(
            s,
            aSuggestions.type,
            visibleOperationsMap,
            context.triggerCharacter,
            aSuggestions.range
          )
        ),
      };
    },
    [indexPattern, visibleOperationsMap, unifiedSearch, dataViews, data.query.timefilter.timefilter]
  );

  const provideSignatureHelp = useCallback(
    async (
      model: monaco.editor.ITextModel,
      position: monaco.Position,
      token: monaco.CancellationToken,
      context: monaco.languages.SignatureHelpContext
    ) => {
      const innerText = model.getValue();
      const textRange = model.getFullModelRange();

      const lengthAfterPosition = model.getValueLengthInRange({
        startLineNumber: position.lineNumber,
        startColumn: position.column,
        endLineNumber: textRange.endLineNumber,
        endColumn: textRange.endColumn,
      });
      return getSignatureHelp(
        model.getValue(),
        innerText.length - lengthAfterPosition,
        visibleOperationsMap
      );
    },
    [visibleOperationsMap]
  );

  const provideHover = useCallback(
    async (
      model: monaco.editor.ITextModel,
      position: monaco.Position,
      token: monaco.CancellationToken
    ) => {
      const innerText = model.getValue();
      const textRange = model.getFullModelRange();

      const lengthAfterPosition = model.getValueLengthInRange({
        startLineNumber: position.lineNumber,
        startColumn: position.column,
        endLineNumber: textRange.endLineNumber,
        endColumn: textRange.endColumn,
      });
      return getHover(
        model.getValue(),
        innerText.length - lengthAfterPosition,
        visibleOperationsMap
      );
    },
    [visibleOperationsMap]
  );

  const onTypeHandler = useCallback(
    (e: monaco.editor.IModelContentChangedEvent, editor: monaco.editor.IStandaloneCodeEditor) => {
      if (e.isFlush || e.isRedoing || e.isUndoing) {
        return;
      }
      if (e.changes.length === 1) {
        const char = e.changes[0].text;
        if (char !== '=' && char !== "'") {
          return;
        }
        const currentPosition = e.changes[0].range;
        if (currentPosition) {
          const currentText = editor.getValue();
          const offset = monacoPositionToOffset(
            currentText,
            new monaco.Position(currentPosition.startLineNumber, currentPosition.startColumn)
          );
          let tokenInfo = getTokenInfo(currentText, offset + 1);

          if (!tokenInfo && char === "'") {
            // try again this time replacing the current quote with an escaped quote
            const line = currentText;
            const lineEscaped = line.substring(0, offset) + "\\'" + line.substring(offset + 1);
            tokenInfo = getTokenInfo(lineEscaped, offset + 2);
          }

          const isSingleQuoteCase = /'LENS_MATH_MARKER/;
          // Make sure that we are only adding kql='' or lucene='', and also
          // check that the = sign isn't inside the KQL expression like kql='='
          if (tokenInfo) {
            if (
              typeof tokenInfo.ast === 'number' ||
              tokenInfo.ast.type !== 'namedArgument' ||
              !namedArgumentsTypes.has(tokenInfo.ast.name) ||
              (tokenInfo.ast.value !== MARKER && !isSingleQuoteCase.test(tokenInfo.ast.value))
            ) {
              return;
            }
          }

          let editOperation: monaco.editor.IIdentifiedSingleEditOperation | null = null;

          const cursorOffset = 2;
          if (char === '=') {
            // check also the previous char whether it was already a =
            // to avoid infinite loops
            if (!tokenInfo && currentText.charAt(offset - 1) !== '=') {
              editOperation = createEditOperation('=', currentPosition, 1);
            }
            if (tokenInfo) {
              editOperation = createEditOperation(`''`, currentPosition, 1);
            }
          }

          if (!tokenInfo && !editOperation) {
            return;
          }

          if (
            char === "'" &&
            tokenInfo?.ast &&
            typeof tokenInfo.ast !== 'number' &&
            'name' in tokenInfo.ast &&
            tokenInfo.ast.name !== 'shift' &&
            tokenInfo.ast.name !== 'reducedTimeRange'
          ) {
            editOperation = createEditOperation(`\\'`, currentPosition);
          }

          if (editOperation) {
            setTimeout(() => {
              editor.executeEdits(
                'LENS',
                [editOperation!],
                [
                  // After inserting, move the cursor in between the single quotes or after the escaped quote
                  new monaco.Selection(
                    currentPosition.startLineNumber,
                    currentPosition.startColumn + cursorOffset,
                    currentPosition.startLineNumber,
                    currentPosition.startColumn + cursorOffset
                  ),
                ]
              );

              // Need to move these sync to prevent race conditions between a fast user typing a single quote
              // after an = char
              // Timeout is required because otherwise the cursor position is not updated.
              editor.setPosition({
                column: currentPosition.startColumn + cursorOffset,
                lineNumber: currentPosition.startLineNumber,
              });
              if (editOperation?.text !== '=') {
                editor.trigger('lens', 'editor.action.triggerSuggest', {});
              }
            }, 0);
          }
        }
      }
    },
    []
  );

  const codeEditorOptions: CodeEditorProps = {
    languageId: LANGUAGE_ID,
    value: text ?? '',
    onChange: setText,
    options: {
      automaticLayout: true,
      fontSize: 14,
      folding: false,
      lineNumbers: 'off',
      scrollBeyondLastLine: false,
      minimap: { enabled: false },
      wordWrap: isWordWrapped ? 'on' : 'off',
      // Disable suggestions that appear when we don't provide a default suggestion
      wordBasedSuggestions: false,
      autoIndent: 'brackets',
      wrappingIndent: 'none',
      dimension: { width: 320, height: 200 },
      fixedOverflowWidgets: true,
      matchBrackets: 'always',
      // Undocumented Monaco option to force left margin width
      lineDecorationsWidth: 16,
    },
  };

  useEffect(() => {
    // Because the monaco model is owned by Lens, we need to manually attach and remove handlers
    const { dispose: dispose1 } = monaco.languages.registerCompletionItemProvider(LANGUAGE_ID, {
      triggerCharacters: ['.', '(', '=', ' ', ':', `'`],
      provideCompletionItems,
    });
    const { dispose: dispose2 } = monaco.languages.registerSignatureHelpProvider(LANGUAGE_ID, {
      signatureHelpTriggerCharacters: ['(', '='],
      provideSignatureHelp,
    });
    const { dispose: dispose3 } = monaco.languages.registerHoverProvider(LANGUAGE_ID, {
      provideHover,
    });
    return () => {
      dispose1();
      dispose2();
      dispose3();
    };
  }, [provideCompletionItems, provideSignatureHelp, provideHover]);

  // The Monaco editor will lazily load Monaco, which takes a render cycle to trigger. This can cause differences
  // in the behavior of Monaco when it's first loaded and then reloaded.
  return (
    <div
      css={[
        sharedEditorStyles.self(euiThemeContext),
        isFullscreen ? fullscreenEditorStyles : defaultEditorStyles,
      ]}
    >
      {!isFullscreen && (
        <EuiFormLabel
          css={css`
            margin-top: ${euiTheme.size.base};
            margin-bottom: ${euiTheme.size.xs};
          `}
        >
          {i18n.translate('xpack.lens.indexPattern.dimensionEditor.headingFormula', {
            defaultMessage: 'Formula',
          })}
        </EuiFormLabel>
      )}

      <div
        className="lnsFormula"
        css={css({
          backgroundColor: euiTheme.colors.backgroundBaseSubdued,
          border: isFullscreen ? 'none' : euiTheme.border.thin,
          borderRadius: isFullscreen ? 0 : euiTheme.border.radius.medium,
          height: isFullscreen ? '100%' : 'auto',
        })}
      >
        <div
          className="lnsFormula__editor"
          css={css`
            & > * + * {
              border-top: ${euiTheme.border.thin};
            }
          `}
        >
          <div css={sharedEditorStyles.editorHeader(euiThemeContext)}>
            <EuiFlexGroup alignItems="center" gutterSize="m" responsive={false}>
              <EuiFlexItem
                css={css`
                  display: block;
                `}
              >
                <EuiToolTip
                  content={
                    isWordWrapped
                      ? i18n.translate('xpack.lens.formula.disableWordWrapLabel', {
                          defaultMessage: 'Disable word wrap',
                        })
                      : i18n.translate('xpack.lens.formulaEnableWordWrapLabel', {
                          defaultMessage: 'Enable word wrap',
                        })
                  }
                  position="top"
                  disableScreenReaderOutput
                >
                  <EuiButtonIcon
                    iconType={isWordWrapped ? 'wordWrap' : 'wordWrapDisabled'}
                    display={!isWordWrapped ? 'fill' : undefined}
                    color={'text'}
                    aria-label={
                      isWordWrapped
                        ? i18n.translate('xpack.lens.formula.disableWordWrapLabel', {
                            defaultMessage: 'Disable word wrap',
                          })
                        : i18n.translate('xpack.lens.formulaEnableWordWrapLabel', {
                            defaultMessage: 'Enable word wrap',
                          })
                    }
                    isSelected={!isWordWrapped}
                    onClick={() => {
                      editor1.current?.updateOptions({
                        wordWrap: isWordWrapped ? 'off' : 'on',
                      });
                      toggleWordWrap(!isWordWrapped);
                    }}
                  />
                </EuiToolTip>
              </EuiFlexItem>

              <EuiFlexItem
                css={css`
                  display: block;
                `}
                grow={false}
              >
                <EuiButtonEmpty
                  onClick={() => {
                    toggleFullscreen();
                    // Help text opens when entering full screen, and closes when leaving full screen
                    setIsHelpOpen(!isFullscreen);
                  }}
                  iconType={isFullscreen ? 'fullScreenExit' : 'fullScreen'}
                  size="xs"
                  color="text"
                  flush="right"
                  data-test-subj="lnsFormula-fullscreen"
                >
                  {isFullscreen
                    ? i18n.translate('xpack.lens.formula.fullScreenExitLabel', {
                        defaultMessage: 'Collapse',
                      })
                    : i18n.translate('xpack.lens.formula.fullScreenEnterLabel', {
                        defaultMessage: 'Expand',
                      })}
                </EuiButtonEmpty>
              </EuiFlexItem>
            </EuiFlexGroup>
          </div>

          <div className="lnsFormula__editorContent">
            <CodeEditor
              {...codeEditorOptions}
              transparentBackground={true}
              options={{
                ...codeEditorOptions.options,
                // Shared model and overflow node
                overflowWidgetsDomNode: overflowDiv1.current,
              }}
              editorDidMount={(editor) => {
                editor1.current = editor;
                const model = editor.getModel();
                if (model) {
                  editorModel.current = model;
                }
                // If we ever introduce a second Monaco editor, we need to toggle
                // the typing handler to the active editor to maintain the cursor
                disposables.current.push(
                  editor.onDidChangeModelContent((e) => {
                    onTypeHandler(e, editor);
                  })
                );
              }}
            />

            {!text ? (
              <div css={sharedEditorStyles.editorPlaceholder(euiThemeContext)}>
                <EuiText color="subdued" size="s">
                  {i18n.translate('xpack.lens.formulaPlaceholderText', {
                    defaultMessage: 'Type a formula by combining functions with math, like:',
                  })}
                </EuiText>
                <EuiSpacer size="s" />
                <pre>count() + 1</pre>
              </div>
            ) : null}
          </div>

          <div css={sharedEditorStyles.editorFooter(euiThemeContext)}>
            <EuiFlexGroup alignItems="center" gutterSize="m" responsive={false}>
              <EuiFlexItem grow={false}>
                {isFullscreen ? (
                  <EuiToolTip
                    content={
                      isHelpOpen
                        ? i18n.translate('xpack.lens.formula.editorHelpInlineHideToolTip', {
                            defaultMessage: 'Hide function reference',
                          })
                        : i18n.translate('xpack.lens.formula.editorHelpInlineShowToolTip', {
                            defaultMessage: 'Show function reference',
                          })
                    }
                    delay="long"
                    position="top"
                  >
                    <EuiLink
                      aria-label={i18n.translate('xpack.lens.formula.editorHelpInlineHideLabel', {
                        defaultMessage: 'Hide function reference',
                      })}
                      className="lnsFormula__editorHelp lnsFormula__editorHelp--inline"
                      css={sharedEditorStyles.editorHelpLink(euiThemeContext)}
                      color="text"
                      onClick={() => setIsHelpOpen(!isHelpOpen)}
                    >
                      <EuiIcon type="documentation" />
                      <EuiIcon type={isHelpOpen ? 'arrowDown' : 'arrowUp'} />
                    </EuiLink>
                  </EuiToolTip>
                ) : (
                  <LanguageDocumentationPopover
                    language="Formula"
                    sections={documentationSections}
                    buttonProps={{
                      color: 'text',
                      className: 'lnsFormula__editorHelp lnsFormula__editorHelp--overlay',
                      'data-test-subj': 'ESQLEditor-documentation',
                      'aria-label': i18n.translate(
                        'xpack.lens.formula.editorHelpInlineShowToolTip',
                        {
                          defaultMessage: 'Show function reference',
                        }
                      ),
                    }}
                    isHelpMenuOpen={isHelpOpen}
                    onHelpMenuVisibilityChange={setIsHelpOpen}
                  />
                )}
              </EuiFlexItem>

              {errorCount || warningCount ? (
                <EuiFlexItem grow={false}>
                  <EuiPopover
                    ownFocus={false}
                    isOpen={isWarningOpen}
                    closePopover={() => setIsWarningOpen(false)}
                    button={
                      <EuiButtonEmpty
                        color={errorCount ? 'danger' : 'warning'}
                        css={css`
                          white-space: nowrap;
                        `}
                        className="lnsFormula__editorError"
                        iconType="warning"
                        size="xs"
                        flush="right"
                        onClick={() => {
                          setIsWarningOpen(!isWarningOpen);
                        }}
                      >
                        {errorCount
                          ? i18n.translate('xpack.lens.formulaErrorCount', {
                              defaultMessage: '{count} {count, plural, one {error} other {errors}}',
                              values: { count: errorCount },
                            })
                          : null}
                        {warningCount
                          ? i18n.translate('xpack.lens.formulaWarningCount', {
                              defaultMessage:
                                '{count} {count, plural, one {warning} other {warnings}}',
                              values: { count: warningCount },
                            })
                          : null}
                      </EuiButtonEmpty>
                    }
                  >
                    <div
                      css={css`
                        max-width: ${euiTheme.components.forms.maxWidth};
                      `}
                    >
                      {warnings.map(({ message, severity }, index) => (
                        <div
                          key={index}
                          css={index !== 0 && sharedEditorStyles.warningText(euiThemeContext)}
                        >
                          <EuiText
                            size="s"
                            color={
                              severity === monaco.MarkerSeverity.Warning ? 'warning' : 'danger'
                            }
                          >
                            {message}
                          </EuiText>
                        </div>
                      ))}
                    </div>
                  </EuiPopover>
                </EuiFlexItem>
              ) : null}
            </EuiFlexGroup>
          </div>
        </div>

        {/* fix the css here */}
        {isFullscreen && isHelpOpen ? (
          <div
            className="documentation__docs--inline"
            css={sharedEditorStyles.formulaDocs(euiThemeContext)}
          >
            <LanguageDocumentationPopoverContent
              language="Formula"
              sections={documentationSections}
            />
          </div>
        ) : null}
      </div>
    </div>
  );
}

const sharedEditorStyles = {
  self: ({ euiTheme }: UseEuiTheme) => {
    return css`
      .lnsFormula {
        display: flex;
        flex-direction: column;

        & > * {
          flex: 1;
          min-height: 0;
        }

        & > * + * {
          border-top: ${euiTheme.border.thin};
        }
      }

      .lnsFormulaOverflow {
        // Needs to be higher than the modal and all flyouts
        z-index: ${euiTheme.levels.toast} + 1;
      }

      .lnsFormula__editorContent {
        background-color: ${euiTheme.colors.backgroundBasePlain};
        min-height: 0;
        position: relative;
      }
    `;
  },
  formulaDocs: ({ euiTheme }: UseEuiTheme) => css`
    display: flex;
    flex-direction: column;
    // make sure docs are rendered in front of monaco
    z-index: 1;
    background: ${euiTheme.colors.backgroundBasePlain};
  `,
  editorHeader: ({ euiTheme }: UseEuiTheme) => css`
    padding: ${euiTheme.size.s};
  `,
  editorFooter: ({ euiTheme }: UseEuiTheme) => css`
    padding: ${euiTheme.size.s};
    // make sure docs are rendered in front of monaco
    z-index: 1;
    border-bottom-right-radius: ${euiTheme.border.radius.medium};
    border-bottom-left-radius: ${euiTheme.border.radius.medium};
  `,
  editorPlaceholder: ({ euiTheme }: UseEuiTheme) => css`
    position: absolute;
    top: 0;
    left: ${euiTheme.size.base};
    right: 0;
    color: ${euiTheme.colors.textSubdued}
    // Matches monaco editor
    font-family: Menlo, Monaco, 'Courier New', monospace;
    pointer-events: none;
  `,
  warningText: ({ euiTheme }: UseEuiTheme) => css`
    margin-top: ${euiTheme.size.s};
    border-top: ${euiTheme.border.thin};
    padding-top: ${euiTheme.size.s};
  `,
  editorHelpLink: ({ euiTheme }: UseEuiTheme) => css`
    align-items: center;
    display: flex;
    padding: ${euiTheme.size.xs};

    & > * + * {
      margin-left: ${euiTheme.size.xs};
    }
  `,
};

const defaultEditorStyles = css`
  .lnsFormula__editorContent {
    height: 200px;
  }
`;

const fullscreenEditorStyles = css`
  position: absolute;
  left: 0;
  right: 0;
  top: 0;
  bottom: 0;

  .lnsFormula__editor {
    border-bottom: none;
    display: flex;
    flex-direction: column;
  }

  .lnsFormula__editorContent {
    flex: 1;
  }
`;
