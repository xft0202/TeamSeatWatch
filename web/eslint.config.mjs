import js from '@eslint/js';
import babelParser from '@babel/eslint-parser';

export default [
  js.configs.recommended,
  {
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: {
      parser: babelParser,
      parserOptions: {
        requireConfigFile: false,
        babelOptions: {
          presets: [
            '@babel/preset-typescript',
            '@babel/preset-react',
          ],
        },
      },
    },
    rules: {
      // TypeScript performs name and unused-binding checks with type awareness.
      'no-undef': 'off',
      'no-unused-vars': 'off',
    },
  },
];
