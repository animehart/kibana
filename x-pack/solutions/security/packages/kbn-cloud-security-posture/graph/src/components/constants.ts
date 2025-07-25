/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Whether or not to instruct the graph component to only render nodes and edges that would be visible in the viewport.
 */
export const ONLY_RENDER_VISIBLE_ELEMENTS = true as const;

/**
 * The size of the grid used for layout and snapping, in pixels.
 */
export const GRID_SIZE = 10;

/**
 * The vertical padding between nodes when being stacked, in pixels.
 */
export const STACK_NODE_VERTICAL_PADDING = 24;

/**
 * The horizontal padding between nodes when being stacked, in pixels.
 */
export const STACK_NODE_HORIZONTAL_PADDING = 20;

/**
 * Minimum height of a stack node, in pixels.
 * Must be a multiple of `GRID_SIZE * 2`.
 */
export const STACK_NODE_MIN_HEIGHT = 60;

export { NODE_WIDTH, NODE_HEIGHT, NODE_LABEL_WIDTH, NODE_LABEL_HEIGHT } from './node/styles';
