/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * ESLint flat config. Type checking is handled by `tsc` (see tsconfig strict mode), so
 * type-level rules (no-unused-vars, etc.) are delegated there to avoid duplicate failures.
 * This layer focuses on runtime/lint hazards: undefined globals, React hook rules, and
 * explicit `any` / empty-type smells surfaced as warnings.
 *
 * Released under the MIT License.
 */

import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import react from "eslint-plugin-react";
import globals from "globals";

export default [
  {
    ignores: [
      "dist",
      "release",
      "node_modules",
      "public",
      "tmp",
      "scripts/**",
      "*.config.ts",
      "*.config.mjs",
      ".vite",
      "coverage",
      "*.config.js"
    ]
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: { ...globals.browser },
      parserOptions: { ecmaFeatures: { jsx: true } }
    },
    plugins: {
      "react-hooks": reactHooks,
      react
    },
    settings: {
      react: { version: "detect" }
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react/react-in-jsx-scope": "off",
      "react/prop-types": "off",
      "@typescript-eslint/no-unused-vars": "off",
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/no-empty-object-type": "warn",
      "@typescript-eslint/no-unsafe-function-type": "warn",
      "no-undef": "off",
      "no-control-regex": "warn",
      "no-useless-escape": "warn"
    }
  }
];
