import js from '@eslint/js'
import globals from 'globals'
import { defineConfig } from 'eslint/config'

export default defineConfig([
  {
    files: ['**/*.{js,mjs,cjs}'],
    plugins: { js },
    extends: ['js/recommended'],
    rules: {
      // --- Best Practices ---
      'no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_'
        }
      ],
      'no-console': process.env.NODE_ENV === 'production' ? 'error' : 'off',
      eqeqeq: ['error', 'always'], // Enforce strict equality (===)
      curly: ['error', 'all'], // Require curly braces for all control blocks
      'no-multi-spaces': 'error', // Disallow multiple spaces
      'no-var': 'error', // Disallow `var`, prefer `let` or `const`
      'prefer-const': 'error', // Prefer `const` when variables are not reassigned
      'no-undef': 'error', // Disallow usage of undeclared variables

      // --- Style Rules ---
      indent: ['error', 2], // Enforce 2-space indentation
      semi: ['error', 'never'], // Disallow semicolons
      quotes: ['error', 'single'], // Enforce single quotes
      'object-curly-spacing': ['error', 'always'], // Require spacing inside curly braces
      'array-bracket-spacing': ['error', 'never'], // Disallow spaces inside array brackets
      'comma-dangle': ['error', 'never'], // Disallow trailing commas
      'key-spacing': ['error', { beforeColon: false, afterColon: true }], // Spacing around colons in object literals
      'space-before-blocks': ['error', 'always'], // Require space before blocks
      'keyword-spacing': ['error', { before: true, after: true }], // Require spacing around keywords
      'eol-last': ['error', 'always'], // Ensure newline at end of file
      'no-trailing-spaces': 'error', // Disallow trailing spaces

      // --- ES6+ and Functional Preferences ---
      'arrow-spacing': ['error', { before: true, after: true }], // Consistent arrow function spacing
      'prefer-arrow-callback': 'error', // Prefer arrow functions for callbacks
      'no-duplicate-imports': 'error', // Disallow duplicate imports
      'object-shorthand': ['error', 'always'] // Require shorthand syntax in object literals
    }
  },
  {
    files: ['**/*.js'],
    languageOptions: {
      sourceType: 'commonjs'
    }
  },
  {
    files: ['**/*.{js,mjs,cjs}'],
    languageOptions: {
      globals: globals.node
    }
  }
])
