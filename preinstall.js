'use strict';

const message = `
  Please use Yarn to install dependencies.

  Run:
    yarn install

  If Yarn is not installed, run:
    npm install -g yarn
`;

const isYarn =
  process.env.npm_execpath &&
  process.env.npm_execpath.indexOf('yarn') !== -1;

if (!isYarn) {
  console.error(message);
  process.exit(1);
}
