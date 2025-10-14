// index.js (Render)
const express = require('express');
const Busboy = require('busboy');
const forge = require('node-forge');

// Полезные полифилы для некоторых окружений
try {
  global.TextEncoder = global.TextEncoder || require('util').TextEncoder;
  global.TextDecoder = global.TextDecoder || require('util').TextDecoder;
} catch {}

const app = express();

// /login — ровно "korolev" без перевода строки
app.get('/login', (req, res) => {
  res.type('text/plain; charset=utf-8').send('korolev');
});

app.post('/decypher', (req, res) => {
  const busboy = new Busboy({ headers: req.headers, limits: { fileSize: 5 * 1024 * 1024 } });

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
      return res.status(400).type('text/plain').send('missing key/secret');
    }

    try {
      // Парсим приватный ключ (PKCS#1 или PKCS#8, без пароля)
      const priv = forge.pki.privateKeyFromPem(privateKeyPem);

      // Поддержка текстовых представлений секрета
      const asText = encryptedBuffer.toString('utf8').trim();
      const b64urlLike = /^[A-Za-z0-9\-_]+={0,2}$/.test(asText);
      const b64Like    = /^[A-Za-z0-9+/=\r\n]+$/.test(asText) && asText.replace(/\s+/g, '').length % 4 === 0;
      const hexLike    = /^[0-9a-fA-F\r\n]+$/.test(asText) && asText.replace(/\s+/g, '').length % 2 === 0;

      let cipherBytes = encryptedBuffer;
      if (b64urlLike) {
        const norm = asText.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
        cipherBytes = Buffer.from(norm, 'base64');
      } else if (b64Like) {
        cipherBytes = Buffer.from(asText.replace(/\s+/g, ''), 'base64');
      } else if (hexLike) {
        cipherBytes = Buffer.from(asText.replace(/\s+/g, ''), 'hex');
      }

      // forge ожидает "binary string" (каждый символ = байт)
      const encBinary = forge.util.createBuffer(cipherBytes).getBytes();

      // Попытки: OAEP(SHA-1), OAEP(SHA-256), PKCS#1 v1.5
      const attempts = [
        () => priv.decrypt(encBinary, 'RSA-OAEP', { md: forge.md.sha1.create(),  mgf1: forge.mgf.mgf1.create(forge.md.sha1.create()) }),
        () => priv.decrypt(encBinary, 'RSA-OAEP', { md: forge.md.sha256.create(), mgf1: forge.mgf.mgf1.create(forge.md.sha256.create()) }),
        () => priv.decrypt(encBinary, 'RSAES-PKCS1-V1_5')
      ];

      for (const attempt of attempts) {
        try {
          const plain = attempt();
          return res.type('text/plain; charset=utf-8').send(plain);
        } catch {}
      }

      return res.status(400).type('text/plain').send('cannot decrypt');
    } catch (e) {
      return res.status(400).type('text/plain').send('Ошибка расшифровки: ' + e.message);
    }
  });

  req.pipe(busboy);
});

// Render задаёт порт через env PORT
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
