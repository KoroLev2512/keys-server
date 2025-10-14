const express = require('express');
const Busboy = require('busboy');
const forge = require('node-forge');

// Для редких окружений без TextEncoder/TextDecoder:
try {
  global.TextEncoder = global.TextEncoder || require('util').TextEncoder;
  global.TextDecoder = global.TextDecoder || require('util').TextDecoder;
} catch { /* ок */ }

const app = express();

app.get('/login', (req, res) => {
  res.type('text/plain; charset=utf-8').send('korolev');
});

app.post('/decypher', (req, res) => {
  const busboy = new Busboy({ headers: req.headers });

  let privateKeyPem = '';
  let encryptedBuffer = Buffer.alloc(0);

  busboy.on('file', (fieldname, file) => {
    const chunks = [];
    file.on('data', d => chunks.push(d));
    file.on('end', () => {
      const buf = Buffer.concat(chunks);
      if (fieldname === 'key') {
        privateKeyPem = buf.toString('utf8');
      } else if (fieldname === 'secret') {
        encryptedBuffer = buf;
      }
    });
  });

  busboy.on('finish', () => {
    if (!privateKeyPem || encryptedBuffer.length === 0) {
      return res.status(400).type('text/plain').send("missing key/secret");
    }

    try {
      const priv = forge.pki.privateKeyFromPem(privateKeyPem);

      // Поддержка текстовых представлений секрета
      let dataBytes = encryptedBuffer;
      const asText = encryptedBuffer.toString('utf8').trim();
      const b64urlLike = /^[A-Za-z0-9\-_]+={0,2}$/.test(asText);
      const b64Like    = /^[A-Za-z0-9+/=\r\n]+$/.test(asText) && asText.replace(/\s+/g,'').length % 4 === 0;
      const hexLike    = /^[0-9a-fA-F\r\n]+$/.test(asText) && asText.replace(/\s+/g,'').length % 2 === 0;

      if (b64urlLike) {
        const norm = asText.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g,'');
        dataBytes = Buffer.from(norm, 'base64');
      } else if (b64Like) {
        dataBytes = Buffer.from(asText.replace(/\s+/g,''), 'base64');
      } else if (hexLike) {
        dataBytes = Buffer.from(asText.replace(/\s+/g,''), 'hex');
      }

      // forge ожидает binary-string
      const encBinary = dataBytes.toString('binary');

      // Пытаемся в порядке: OAEP(SHA-1) -> OAEP(SHA-256) -> PKCS#1 v1.5
      let plaintext = null;
      try {
        plaintext = priv.decrypt(encBinary, 'RSA-OAEP', { md: forge.md.sha1.create() });
      } catch {}
      if (plaintext === null) {
        try {
          plaintext = priv.decrypt(encBinary, 'RSA-OAEP', { md: forge.md.sha256.create() });
        } catch {}
      }
      if (plaintext === null) {
        try {
          plaintext = priv.decrypt(encBinary, 'RSAES-PKCS1-V1_5');
        } catch {}
      }

      if (plaintext === null) {
        return res.status(400).type('text/plain').send('cannot decrypt');
      }
      return res.type('text/plain; charset=utf-8').send(plaintext);
    } catch (e) {
      return res.status(400).type('text/plain').send('Ошибка расшифровки: ' + e.message);
    }
  });

  req.pipe(busboy);
});

// Render фиксирует порт через env PORT
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
