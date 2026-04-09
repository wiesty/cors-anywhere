'use strict';

var nodeGlobals = {
  require: 'readonly',
  module: 'readonly',
  exports: 'readonly',
  __dirname: 'readonly',
  __filename: 'readonly',
  process: 'readonly',
  console: 'readonly',
  setTimeout: 'readonly',
  clearTimeout: 'readonly',
  setInterval: 'readonly',
  clearInterval: 'readonly',
  Buffer: 'readonly',
  global: 'readonly',
};

var mochaGlobals = {
  describe: 'readonly',
  it: 'readonly',
  before: 'readonly',
  after: 'readonly',
  beforeEach: 'readonly',
  afterEach: 'readonly',
};

module.exports = [
  {
    ignores: ['coverage/', 'node_modules/'],
  },
  {
    languageOptions: {
      ecmaVersion: 2020,
      globals: nodeGlobals,
    },
    rules: {
      'array-bracket-spacing': ['error', 'never'],
      'block-scoped-var': 'error',
      'brace-style': ['error', '1tbs', {allowSingleLine: true}],
      'comma-dangle': ['error', 'always-multiline'],
      'computed-property-spacing': ['error', 'never'],
      'curly': 'error',
      'eol-last': 'error',
      'eqeqeq': ['error', 'smart'],
      'max-len': ['warn', 125],
      'new-cap': 'warn',
      'no-extend-native': 'error',
      'no-mixed-spaces-and-tabs': 'error',
      'no-trailing-spaces': 'error',
      'no-undef': 'error',
      'no-unused-vars': 'warn',
      'no-use-before-define': ['error', {functions: false}],
      'object-curly-spacing': ['error', 'never'],
      'quotes': ['error', 'single', 'avoid-escape'],
      'semi': ['error', 'always'],
      'keyword-spacing': 'error',
      'space-unary-ops': 'error',
    },
  },
  {
    files: ['test/**/*.js'],
    languageOptions: {
      globals: mochaGlobals,
    },
  },
];
