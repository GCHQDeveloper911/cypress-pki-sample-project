var fs = require('fs-extra');

const path = require('path');
const Forge = require('node-forge');
const Promise = require('bluebird');
const _ = require('lodash');

const { pki, pkcs12, asn1 } = Forge;

fs = Promise.promisifyAll(fs)

const ipAddressRe = /^[\d\.]+$/
const asterisksRe = /\*/g
const generateKeyPairAsync = Promise.promisify(pki.rsa.generateKeyPair)

const CAattrs = [
  {
    name: 'commonName',
    value: 'CypressProxyCA',
  }, {
    name: 'countryName',
    value: 'Internet',
  }, {
    shortName: 'ST',
    value: 'Internet',
  }, {
    name: 'localityName',
    value: 'Internet',
  }, {
    name: 'organizationName',
    value: 'Cypress.io',
  }, {
    shortName: 'OU',
    value: 'CA',
  }
]
const CAextensions = [
  {
    name: 'basicConstraints',
    ca: true,
  }, {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true,
  }, {
    name: 'extKeyUsage',
    serverAuth: true,
    clientAuth: true,
    codeSigning: true,
    emailProtection: true,
    timeStamping: true,
  }, {
    name: 'nsCertType',
    client: true,
    server: true,
    email: true,
    objsign: true,
    sslCA: true,
    emailCA: true,
    objCA: true,
  }, {
    name: 'subjectKeyIdentifier',
  }
]

const ServerAttrs = [{
  name: 'countryName',
  value: 'Internet',
}, {
  shortName: 'ST',
  value: 'Internet',
}, {
  name: 'localityName',
  value: 'Internet',
}, {
  name: 'organizationName',
  value: 'Cypress Proxy CA',
}, {
  shortName: 'OU',
  value: 'Cypress Proxy Server Certificate',
}]

const ServerExtensions = [{
  name: 'basicConstraints',
  cA: false,
}, {
  name: 'keyUsage',
  keyCertSign: false,
  digitalSignature: true,
  nonRepudiation: false,
  keyEncipherment: true,
  dataEncipherment: true,
}, {
  name: 'extKeyUsage',
  serverAuth: true,
  clientAuth: true,
  codeSigning: false,
  emailProtection: false,
  timeStamping: false,
}, {
  name: 'nsCertType',
  client: true,
  server: true,
  email: false,
  objsign: false,
  sslCA: false,
  emailCA: false,
  objCA: false,
}, {
  name: 'subjectKeyIdentifier',
}]

const ClientExtensions = [{
  name: 'basicConstraints',
  cA: false,
}, {
  name: 'keyUsage',
  keyCertSign: false,
  digitalSignature: true,
  nonRepudiation: false,
  keyEncipherment: true,
  dataEncipherment: true,
}, {
  name: 'extKeyUsage',
  serverAuth: true,
  clientAuth: true,
  codeSigning: false,
  emailProtection: false,
  timeStamping: false,
}, {
  name: 'nsCertType',
  client: true,
  server: true,
  email: false,
  objsign: false,
  sslCA: false,
  emailCA: false,
  objCA: false,
}, {
  name: 'subjectKeyIdentifier',
}]

class CA {
  constructor () {
    this.certsFolder = path.join(path.resolve(__dirname), '..', 'certs');

    this.CAcert = null;
    this.CAkeys = null;
  }

  randomSerialNumber () {
    // generate random 16 bytes hex string
    let sn = ''

    for (let i = 1; i <= 4; i++) {
      sn += (`00000000${Math.floor(Math.random() * Math.pow(256, 4)).toString(16)}`).slice(-8)
    }

    return sn
  }

  generateCA () {
    return generateKeyPairAsync({ bits: 2048 })
      .then((keys) => {
        const cert = pki.createCertificate()

        cert.publicKey = keys.publicKey
        cert.serialNumber = this.randomSerialNumber()

        cert.validity.notBefore = new Date()
        cert.validity.notAfter = new Date()
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10)
        cert.setSubject(CAattrs)
        cert.setIssuer(CAattrs)
        cert.setExtensions(CAextensions)
        cert.sign(keys.privateKey, Forge.md.sha256.create())

        this.CAcert = cert
        this.CAkeys = keys

        return Promise.all([
          fs.outputFileAsync(path.join(this.certsFolder, 'ca', 'ca.pem'), pki.certificateToPem(cert)),
          fs.outputFileAsync(path.join(this.certsFolder, 'ca', 'ca.private.key'), pki.privateKeyToPem(keys.privateKey)),
          fs.outputFileAsync(path.join(this.certsFolder, 'ca', 'ca.public.key'), pki.publicKeyToPem(keys.publicKey)),
        ])
      })
  }

  generateServerCertificateKeys (hosts) {
    hosts = [].concat(hosts)

    const mainHost = hosts[0]
    const keysServer = pki.rsa.generateKeyPair(2048)
    const certServer = pki.createCertificate()

    certServer.publicKey = keysServer.publicKey
    certServer.serialNumber = this.randomSerialNumber()
    certServer.validity.notBefore = new Date
    certServer.validity.notAfter = new Date
    certServer.validity.notAfter.setFullYear(certServer.validity.notBefore.getFullYear() + 2)

    const attrsServer = _.clone(ServerAttrs)

    attrsServer.unshift({
      name: 'commonName',
      value: mainHost,
    })

    certServer.setSubject(attrsServer)
    certServer.setIssuer(this.CAcert.issuer.attributes)
    certServer.setExtensions(ServerExtensions.concat([{
      name: 'subjectAltName',
      altNames: hosts.map((host) => {
        if (host.match(ipAddressRe)) {
          return { type: 7, ip: host }
        }

        return { type: 2, value: host }
      }),
    }]))

    certServer.sign(this.CAkeys.privateKey, Forge.md.sha256.create())

    const certPem = pki.certificateToPem(certServer)
    const keyPrivatePem = pki.privateKeyToPem(keysServer.privateKey)
    const keyPublicPem = pki.publicKeyToPem(keysServer.publicKey)

    const dest = mainHost.replace(asterisksRe, '_')

    return Promise.all([
      fs.outputFileAsync(path.join(this.certsFolder, 'server', `${dest}.pem`), certPem),
      fs.outputFileAsync(path.join(this.certsFolder, 'server', `${dest}.key`), keyPrivatePem),
      fs.outputFileAsync(path.join(this.certsFolder, 'server', `${dest}.public.key`), keyPublicPem),
    ])
    .return([certPem, keyPrivatePem])
  }

  generateClientCertificateKey (commonName, type) {
    const keysClient = pki.rsa.generateKeyPair(2048)
    const certClient = pki.createCertificate()

    certClient.publicKey = keysClient.publicKey
    certClient.serialNumber = this.randomSerialNumber()
    certClient.validity.notBefore = new Date
    certClient.validity.notAfter = new Date
    certClient.validity.notAfter.setFullYear(certClient.validity.notBefore.getFullYear() + 2)

    let attrsClient = [
      {
        shortName: 'CN',
        value: commonName,
      },
      {
        shortName: 'OU',
        value: 'Users'
      },
      {
        shortName: 'O',
        value: 'Cypress'
      }
    ]

    certClient.setSubject(attrsClient)
    certClient.setExtensions(ClientExtensions)

    certClient.setIssuer(this.CAcert.issuer.attributes)
    certClient.sign(this.CAkeys.privateKey, Forge.md.sha256.create())

    if (type === "PEM") {
      const certPem = pki.certificateToPem(certClient)
      const keyPrivatePem = pki.privateKeyToPem(keysClient.privateKey)
      const keyPublicPem = pki.publicKeyToPem(keysClient.publicKey)

      return Promise.all([
        fs.outputFileAsync(path.join(this.certsFolder, `client/${commonName}`, `cert.pem`), certPem),
        fs.outputFileAsync(path.join(this.certsFolder, `client/${commonName}`, `private.key`), keyPrivatePem),
        fs.outputFileAsync(path.join(this.certsFolder, `client/${commonName}`, `public.key`), keyPublicPem),
      ]).return([certPem, keyPrivatePem])

    }else if (type === "PFX") {
      const pfxPassphrase = `passphrase-${commonName}`;
      const certPfxAsn1 = pkcs12.toPkcs12Asn1(keysClient.privateKey, [ certClient ], pfxPassphrase, { algorithm: '3des', generateLocalKeyId: true });
      const certPfxDer = asn1.toDer(certPfxAsn1).getBytes();

      return Promise.all([
        fs.outputFileAsync(path.join(this.certsFolder, `client/${commonName}`, `cert.pfx`), certPfxDer, { encoding: 'binary' }),
        fs.outputFileAsync(path.join(this.certsFolder, `client/${commonName}`, `pfx-passphrase.key`), pfxPassphrase),
      ]).return([certPfxDer, pfxPassphrase])
    }
  }
}

module.exports = CA;