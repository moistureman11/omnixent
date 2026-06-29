export const serviceModuleMock = {
  __esModule: true,
  availableServices: ['google', 'amazon', 'duckduckgo', 'bing', 'youtube'],
  default: jest.fn().mockResolvedValue([
    {
      category: 'search',
      originalTerm: 'hello world',
      term: 'hello world',
      result: ['mocked-result'],
    },
  ]),
};
