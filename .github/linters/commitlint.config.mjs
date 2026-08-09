// Commit-message rules, enforced per pull request by validate-commits.yml.
// Encodes the repo conventions: a conventional `type(scope): Subject` header
// capped at 72 columns with a capitalized, period-free subject, body prose
// wrapped at 72, and a Signed-off-by trailer (DCO).
export default {
  extends: ['@commitlint/config-conventional'],
  helpUrl: 'https://www.conventionalcommits.org/',
  plugins: [
    {
      rules: {
        // Wrap body prose, but exempt trailers and markdown table rows: each is
        // a single logical record that folding would corrupt, and some trailers
        // carry long URLs. The table is the dependency update table Renovate
        // writes into its commit bodies.
        'body-max-line-length': (parsed, _when, value) => {
          const { body } = parsed;
          if (!body) return [true, ''];

          const trailerPattern =
            /^(Signed-off-by|Co-authored-by|Reviewed-by|Approved-by|Fixes|Refs):/;
          const tableRowPattern = /^\|.*\|$/;
          const unfoldable = (line) =>
            trailerPattern.test(line) || tableRowPattern.test(line);
          const violation = body
            .split('\n')
            .find((line) => line.length > value && !unfoldable(line));

          return [
            !violation,
            violation
              ? `body lines must not be longer than ${value} characters ` +
                `(found: "${violation}")`
              : '',
          ];
        },
      },
    },
  ],
  rules: {
    // Conventional types in use across the history, plus revert.
    'type-enum': [
      2,
      'always',
      [
        'build',
        'chore',
        'ci',
        'docs',
        'feat',
        'fix',
        'perf',
        'refactor',
        'revert',
        'style',
        'test',
      ],
    ],
    // Scopes are lowercase (machine, x86, virtio, boot, layout, ci).
    // Case is all that is held: a stricter kebab-case rule rejects a digit or
    // an underscore, and scopes like `x86` and `uart16550` carry both. A bare
    // type with no scope stays allowed.
    'scope-case': [2, 'always', 'lower-case'],
    // Subjects are capitalized prose. Blocklist the shapes that are not, rather
    // than requiring sentence-case, which would reject an embedded identifier
    // or acronym (for example "Add TLS SNI capture").
    'subject-case': [
      2,
      'never',
      [
        'lower-case', // lower case
        'upper-case', // UPPERCASE
        'camel-case', // camelCase
        'kebab-case', // kebab-case
        'pascal-case', // PascalCase
        'snake-case', // snake_case
        'start-case', // Start Case
      ],
    ],
    'subject-full-stop': [2, 'never', '.'],
    'header-max-length': [2, 'always', 72],
    'body-max-line-length': [2, 'always', 72],
    // DCO: every commit carries a Signed-off-by trailer.
    'trailer-exists': [2, 'always', 'Signed-off-by:'],
  },
};
