/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { parse } from '../parser';

describe('FUSE', () => {
  describe('correctly formatted', () => {
    it('can parse FUSE command without modifiers', () => {
      const text = `FROM search-movies METADATA _score, _id, _index
                    | FORK
                      ( WHERE semantic_title:"Shakespeare" | SORT _score)
                      ( WHERE title:"Shakespeare" | SORT _score)
                    | FUSE
                    | KEEP title, _score`;

      const { root, errors } = parse(text);

      expect(errors.length).toBe(0);
      expect(root.commands[2]).toMatchObject({
        type: 'command',
        name: 'fuse',
        args: [],
      });
    });
  });

  describe('when incorrectly formatted, return errors', () => {
    it('when no pipe after', () => {
      const text = `FROM search-movies METADATA _score, _id, _index
                      | FORK
                        ( WHERE semantic_title:"Shakespeare" | SORT _score)
                        ( WHERE title:"Shakespeare" | SORT _score)
                      | FUSE KEEP title, _score`;

      const { errors } = parse(text);

      expect(errors.length > 0).toBe(true);
    });

    it('when no pipe between FORK and FUSE', () => {
      const text = `FROM search-movies METADATA _score, _id, _index
                    | FORK
                      ( WHERE semantic_title:"Shakespeare" | SORT _score)
                      ( WHERE title:"Shakespeare" | SORT _score) FUSE`;

      const { errors } = parse(text);

      expect(errors.length > 0).toBe(true);
    });

    it('when FUSE is invoked with arguments', () => {
      const text = `FROM search-movies METADATA _score, _id, _index
                    | FORK ( WHERE semantic_title:"Shakespeare" | SORT _score)
                              ( WHERE title:"Shakespeare" | SORT _score)
                    | FUSE text`;

      const { errors } = parse(text);

      expect(errors.length > 0).toBe(true);
    });
  });
});
