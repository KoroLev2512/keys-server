import express from "express";
import multer from "multer";
import forge from "node-forge";

const app = express();
const LOGIN = "korolev";

// Настройка multer для обработки multipart/form-data
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB лимит
  },
});

// Маршрут для получения логина
app.get("/login", (req, res) => {
  res.type("text/plain").send(LOGIN);
});

// Маршрут для расшифровки
app.post(
  "/decypher",
  upload.fields([
    { name: "key", maxCount: 1 },
    { name: "secret", maxCount: 1 },
  ]),
  (req, res) => {
    try {
      // Проверяем наличие файлов
      if (!req.files  !req.files.key  !req.files.secret) {
        return res
          .status(400)
          .type("text/plain")
          .send("Отсутствуют обязательные поля: key и secret");
      }

      const keyFile = req.files.key[0];
      const secretFile = req.files.secret[0];

      // Получаем содержимое приватного ключа
      const privateKeyPem = keyFile.buffer.toString("utf8");

      // Получаем зашифрованные данные
      const encryptedData = secretFile.buffer;

      // Парсим приватный ключ
      const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

      // Расшифровываем данные
      const decrypted = privateKey.decrypt(
        encryptedData.toString("binary"),
        "RSA-OAEP"
      );

      // Возвращаем результат как обычную строку
      res.type("text/plain").send(decrypted);
    } catch (error) {
      console.error("Ошибка расшифровки:", error);
      res
        .status(400)
        .type("text/plain")
        .send(Ошибка расшифровки: ${error.message});
    }
  }
);

// Корневой маршрут
app.get("/", (req, res) => {
  res.type("text/plain").send("ok");
});

// Обработка ошибок
app.use((err, req, res, next) => {
  console.error("Ошибка сервера:", err);
  res.status(500).type("text/plain").send("Внутренняя ошибка сервера");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(Сервер запущен на порту ${PORT});
});
