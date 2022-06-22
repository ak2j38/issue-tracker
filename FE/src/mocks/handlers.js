import { rest } from 'msw';

// create handlers

// rest.get('url', (req, res, tx))

export const handlers = [
  rest.get('http://localhost:3030/scoops', (req, res, ctx) => {
    return res(
      ctx.json([
        { name: 'Chocolate', imagePath: '/image/chocolate.png' },
        { name: 'Vanilla', imagePath: '/images/vanilla.png' },
      ]),
    );
  }),

  // topping 루트를 위한 핸들러를  추가한다.
  rest.get('http://localhost:3030/toppings', (req, res, ctx) => {
    return res(
      ctx.json([
        { name: 'Cherries', imagePath: '/images/cherries.png' },
        { name: 'M&Ms', imagePath: '/images/m-and-ms.png' },
        { name: 'Hot fudge', imagePath: '/images/hot-fudge.png' },
      ]),
    );
  }),
];
