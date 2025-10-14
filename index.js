import express from "express";
import multer from "multer";
import forge from "node-forge";

const app = express();
const LOGIN = "korolev";

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

app.get("/login", (req, res) => {
  res.type("text/plain").send(LOGIN);
});

app.post(
  "/decypher",
  upload.fields([
    { name: "key", maxCount: 1 },
    { name: "secret", maxCount: 1 },
  ]),
  (req, res) => {
    try {
      // Получаем приватный ключ (файл или поле)
      let privateKeyPem = "";
      if (req.files?.key?.[0]) {
        privateKeyPem = req.files.key[0].buffer.toString("utf8");
      } else if (req.body?.key) {
        privateKeyPem = req.body.key;
      }

      // Получаем зашифрованные данные (файл или поле)
      let encryptedBuffer = Buffer.alloc(0);
      if (req.files?.secret?.[0]) {
        encryptedBuffer = req.files.secret[0].buffer;
      } else if (req.body?.secret) {
        encryptedBuffer = Buffer.from(req.body.secret, "utf8");
      }

      if (!privateKeyPem || !encryptedBuffer.length) {
        return res
          .status(400)
          .type("text/plain")
          .send("missing key/secret");
      }

      const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

      // Определяем формат секрета
      const asText = encryptedBuffer.toString("utf8").trim();
      const b64urlLike = /^[A-Za-z0-9\-_]+={0,2}$/.test(asText);
      const b64Like = /^[A-Za-z0-9+/=\r\n]+$/.test(asText) && asText.replace(/\s+/g, '').length % 4 === 0;
      const hexLike = /^[0-9a-fA-F\r\n]+$/.test(asText) && asText.replace(/\s+/g, '').length % 2 === 0;

      let cipherBytes = encryptedBuffer;
      if (b64urlLike) {
        const norm = asText.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
        cipherBytes = Buffer.from(norm, 'base64');
      } else if (b64Like) {
        cipherBytes = Buffer.from(asText.replace(/\s+/g, ''), 'base64');
      } else if (hexLike) {
        cipherBytes = Buffer.from(asText.replace(/\s+/g, ''), 'hex');
      }

      const encBinary = forge.util.createBuffer(cipherBytes).getBytes();

      // Пробуем разные схемы расшифровки
      const attempts = [
        () => privateKey.decrypt(encBinary, 'RSA-OAEP', { md: forge.md.sha1.create(), mgf1: forge.mgf.mgf1.create(forge.md.sha1.create()) }),
        () => privateKey.decrypt(encBinary, 'RSA-OAEP', { md: forge.md.sha256.create(), mgf1: forge.mgf.mgf1.create(forge.md.sha256.create()) }),
        () => privateKey.decrypt(encBinary, 'RSAES-PKCS1-V1_5')
      ];

      for (const attempt of attempts) {
        try {
          const plain = attempt();
          return res.type("text/plain; charset=utf-8").send(plain);
        } catch {}
      }

      return res.status(400).type("text/plain").send("cannot decrypt");
    } catch (error) {
      console.error("Ошибка расшифровки:", error);
      res
        .status(400)
        .type("text/plain")
        .send(`Ошибка расшифровки: ${error.message}`);
    }
  }
);

app.get("/", (req, res) => {
  res.type("text/plain").send("ok");
});

app.use((err, req, res, next) => {
  console.error("Ошибка сервера:", err);
  res.status(500).type("text/plain").send("Внутренняя ошибка сервера");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});
