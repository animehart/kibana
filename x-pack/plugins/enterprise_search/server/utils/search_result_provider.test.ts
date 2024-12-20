/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { NEVER, of } from 'rxjs';
import { TestScheduler } from 'rxjs/testing';

import type { GlobalSearchProviderContext } from '@kbn/global-search-plugin/server';

import { ENTERPRISE_SEARCH_CONTENT_PLUGIN } from '../../common/constants';

import { getSearchResultProvider } from './search_result_provider';

const getTestScheduler = () => {
  return new TestScheduler((actual, expected) => {
    return expect(actual).toEqual(expected);
  });
};

const getSearchProviderContext = ({
  enterpriseSearchEnabled,
}: {
  enterpriseSearchEnabled: boolean;
}): GlobalSearchProviderContext => ({
  core: {
    capabilities: of({
      catalogue: { enterpriseSearch: enterpriseSearchEnabled },
      management: {},
      navLinks: {},
    }),
    savedObjects: {} as any,
    uiSettings: {} as any,
  },
});
const mockSearchProviderContext = getSearchProviderContext({ enterpriseSearchEnabled: true });

const connectors = [
  {
    categories: [
      'enterprise_search',
      'datastore',
      'elastic_stack',
      'connector',
      'connector_client',
    ],
    description: 'Search over your mongo content',
    iconPath: 'mongodb.svg',
    isBeta: false,
    isNative: true,
    keywords: ['mongo', 'mongodb', 'database', 'nosql', 'connector'],
    name: 'MongoDB',
    serviceType: 'mongodb',
  },
  {
    categories: ['enterprise_search', 'custom', 'elastic_stack', 'connector', 'connector_client'],
    description: 'Search over your data',
    iconPath: 'custom.svg',
    isBeta: true,
    isNative: false,
    keywords: ['custom', 'connector', 'code'],
    name: 'Customized connector',
    serviceType: '',
  },
];

describe('Search search provider', () => {
  const crawlerResult = {
    icon: 'crawlerIcon.svg',
    id: 'elastic-crawler',
    score: 75,
    title: 'Elastic Web Crawler',
    type: 'Elasticsearch',
    url: {
      path: `${ENTERPRISE_SEARCH_CONTENT_PLUGIN.URL}/crawlers/new_crawler`,
      prependBasePath: true,
    },
  };

  const mongoResult = {
    icon: 'mongodb.svg',
    id: 'mongodb',
    score: 75,
    title: 'MongoDB',
    type: 'Elasticsearch',
    url: {
      path: `${ENTERPRISE_SEARCH_CONTENT_PLUGIN.URL}/connectors/new_connector?connector_type=connector_client&service_type=mongodb`,
      prependBasePath: true,
    },
  };

  const nativeMongoResult = {
    icon: 'mongodb.svg',
    id: 'mongodb',
    score: 75,
    title: 'MongoDB',
    type: 'Elasticsearch',
    url: {
      path: `${ENTERPRISE_SEARCH_CONTENT_PLUGIN.URL}/connectors/new_connector?connector_type=native&service_type=mongodb`,
      prependBasePath: true,
    },
  };

  const customizedConnectorResult = {
    icon: 'custom.svg',
    id: '',
    score: 75,
    title: 'Customized connector',
    type: 'Elasticsearch',
    url: {
      path: `${ENTERPRISE_SEARCH_CONTENT_PLUGIN.URL}/connectors/new_connector?connector_type=connector_client&service_type=`,
      prependBasePath: true,
    },
  };

  const searchResultProvider = getSearchResultProvider(
    {
      hasConnectors: true,
      hasWebCrawler: true,
    } as any,
    connectors,
    false,
    'crawlerIcon.svg'
  );

  beforeEach(() => {});

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('find', () => {
    it('returns formatted results', () => {
      getTestScheduler().run(({ expectObservable }) => {
        expectObservable(
          searchResultProvider.find(
            { term: 'crawler' },
            { aborted$: NEVER, maxResults: 100, preference: '' },
            mockSearchProviderContext
          )
        ).toBe('(a|)', {
          a: [crawlerResult],
        });
      });
    });

    it('returns everything on empty string', () => {
      getTestScheduler().run(({ expectObservable }) => {
        expectObservable(
          searchResultProvider.find(
            { term: '' },
            { aborted$: NEVER, maxResults: 100, preference: '' },
            mockSearchProviderContext
          )
        ).toBe('(a|)', {
          a: expect.arrayContaining([
            { ...crawlerResult, score: 80 },
            { ...mongoResult, score: 80 },
          ]),
        });
      });
    });

    it('respect maximum results', () => {
      getTestScheduler().run(({ expectObservable }) => {
        expectObservable(
          searchResultProvider.find(
            { term: '' },
            { aborted$: NEVER, maxResults: 1, preference: '' },
            mockSearchProviderContext
          )
        ).toBe('(a|)', {
          a: [{ ...crawlerResult, score: 80 }],
        });
      });
    });

    it('omits crawler if config has crawler disabled', () => {
      const searchProvider = getSearchResultProvider(
        {
          hasConnectors: true,
          hasWebCrawler: false,
        } as any,
        connectors,
        false,
        'crawlerIcon.svg'
      );
      getTestScheduler().run(({ expectObservable }) => {
        expectObservable(
          searchProvider.find(
            { term: '' },
            { aborted$: NEVER, maxResults: 100, preference: '' },
            mockSearchProviderContext
          )
        ).toBe('(a|)', {
          a: expect.not.arrayContaining([{ ...crawlerResult, score: 80 }]),
        });
      });
    });

    it('omits connectors if config has connectors disabled', () => {
      const searchProvider = getSearchResultProvider(
        {
          hasConnectors: false,
          hasWebCrawler: true,
        } as any,
        connectors,
        false,
        'crawlerIcon.svg'
      );
      getTestScheduler().run(({ expectObservable }) => {
        expectObservable(
          searchProvider.find(
            { term: '' },
            { aborted$: NEVER, maxResults: 100, preference: '' },
            mockSearchProviderContext
          )
        ).toBe('(a|)', {
          a: expect.not.arrayContaining([{ mongoResult, score: 80 }]),
        });
      });
    });

    it('returns nothing if tag is specified', () => {
      getTestScheduler().run(({ expectObservable }) => {
        expectObservable(
          searchResultProvider.find(
            { tags: ['tag'], term: '' },
            { aborted$: NEVER, maxResults: 1, preference: '' },
            mockSearchProviderContext
          )
        ).toBe('(a|)', {
          a: [],
        });
      });
    });

    it('returns nothing if unknown type is specified', () => {
      getTestScheduler().run(({ expectObservable }) => {
        expectObservable(
          searchResultProvider.find(
            { term: '', types: ['tag'] },
            { aborted$: NEVER, maxResults: 1, preference: '' },
            mockSearchProviderContext
          )
        ).toBe('(a|)', {
          a: [],
        });
      });
    });
    it('returns nothing if capabilities.catalogue.enterpriseSearch is false', () => {
      getTestScheduler().run(({ expectObservable }) => {
        expectObservable(
          searchResultProvider.find(
            { term: '', types: ['tag'] },
            { aborted$: NEVER, maxResults: 1, preference: '' },
            getSearchProviderContext({ enterpriseSearchEnabled: false })
          )
        ).toBe('(a|)', {
          a: [],
        });
      });
    });
    it('returns results for integrations tag', () => {
      getTestScheduler().run(({ expectObservable }) => {
        expectObservable(
          searchResultProvider.find(
            { term: 'crawler', types: ['integration'] },
            { aborted$: NEVER, maxResults: 1, preference: '' },
            mockSearchProviderContext
          )
        ).toBe('(a|)', {
          a: [crawlerResult],
        });
      });
    });
    it('returns results for enterprise search tag', () => {
      getTestScheduler().run(({ expectObservable }) => {
        expectObservable(
          searchResultProvider.find(
            { term: 'crawler', types: ['enterprise search'] },
            { aborted$: NEVER, maxResults: 1, preference: '' },
            mockSearchProviderContext
          )
        ).toBe('(a|)', {
          a: [crawlerResult],
        });
      });
    });
    it('does not return results for legacy app search', () => {
      const searchProvider = getSearchResultProvider(
        {
          hasConnectors: false,
          hasWebCrawler: false,
        } as any,
        connectors,
        false,
        'crawlerIcon.svg'
      );
      getTestScheduler().run(({ expectObservable }) => {
        expectObservable(
          searchProvider.find(
            { term: 'app search' },
            { aborted$: NEVER, maxResults: 1, preference: '' },
            mockSearchProviderContext
          )
        ).toBe('(a|)', {
          a: [],
        });
      });
    });
    it('does not return results for legacy workplace search', () => {
      const searchProvider = getSearchResultProvider(
        {
          hasConnectors: false,
          hasWebCrawler: false,
        } as any,
        connectors,
        false,
        'crawlerIcon.svg'
      );
      getTestScheduler().run(({ expectObservable }) => {
        expectObservable(
          searchProvider.find(
            { term: 'workplace search' },
            { aborted$: NEVER, maxResults: 1, preference: '' },
            mockSearchProviderContext
          )
        ).toBe('(a|)', {
          a: [],
        });
      });
    });

    it('returns appropriate native flags when on cloud', () => {
      const searchProvider = getSearchResultProvider(
        {
          hasConnectors: true,
          hasWebCrawler: true,
        } as any,
        connectors,
        true,
        'crawlerIcon.svg'
      );
      getTestScheduler().run(({ expectObservable }) => {
        expectObservable(
          searchProvider.find(
            { term: '' },
            { aborted$: NEVER, maxResults: 100, preference: '' },
            mockSearchProviderContext
          )
        ).toBe('(a|)', {
          a: expect.arrayContaining([
            { ...crawlerResult, score: 80 },
            { ...nativeMongoResult, score: 80 },
            { ...customizedConnectorResult, score: 80 },
          ]),
        });
      });
    });
  });
});
