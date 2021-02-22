const fs = require('fs');
const https = require('https');
const express = require('express');

const CA = require('./ca');

const app = express();

const prepareCerts = async () => {
  try {
    const ca = new CA();
    await ca.generateCA();

    await ca.generateServerCertificateKeys([ "localhost" ]);

    await ca.generateClientCertificateKey("user_pem", "PEM")
    await ca.generateClientCertificateKey("user_pfx", "PFX")

    return Promise.resolve();

  }catch (err) {
    console.log(err);
    process.exit(1);
  }
};


const clientAuthMiddleware = () => (req, res, next) => {
  if (!req.socket.getPeerCertificate(true) || req.socket.getPeerCertificate(true) === {}) {
    return res.status(401).send('No client certificate sent');
  }

  return next();
};

app.use(clientAuthMiddleware());
app.use('/static', express.static('static'));

app.get('/', (req, res) => {
  return res.send('Hello World!');
});

app.get('/whoami/*', (req, res) => {
  return res.send(JSON.stringify(req.socket.getPeerCertificate(true).subject));
});

app.get('/logo/*', (req, res) => {
  return res.send(`
    <html>
      <head>
        <title>Cypress PKI Subrequest Test</title>
        <link rel="stylesheet" type="text/css" href="/static/test.css" />
      </head>
      <body>
        <img src="/static/logo.png" alt="Cypress Logo" />
        <h1>Hello World</h1>
    </html>
  `)
})

prepareCerts()
  .then(() => {
    const ca = [ fs.readFileSync('certs/ca/ca.pem', 'utf-8') ];
    const cert = fs.readFileSync('certs/server/localhost.pem', 'utf-8');
    const key = fs.readFileSync('certs/server/localhost.key', 'utf-8');

    https.createServer({
      requestCert: true,
      rejectUnauthorized: false,
      ca,
      cert,
      key
    }, app).listen(8443);

    console.log("Server Listening on :8443")
  });