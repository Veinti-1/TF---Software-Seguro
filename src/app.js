const express = require('express');
const { initDb } = require('./db/init');
const users = require('./routes/users');
const admin = require('./routes/admin');
const articles = require('./routes/articles');

initDb();
const app = express();
app.use(express.json());
app.use('/api', users);
app.use('/api', admin);
app.use('/api', articles);

app.get('/', (req, res) => res.json({ service: 'conduit-api', status: 'ok' }));

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`conduit-api listening on ${PORT}`));
}
module.exports = app;
