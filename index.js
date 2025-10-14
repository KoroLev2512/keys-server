import { privateDecrypt, constants } from "crypto";
import Busboy from "busboy";

export async function handler (event, context) {
  return new Promise((resolve, reject) => {
    const contentType = event.headers["content-type"] || event.headers["Content-Type"];
    if (!contentType || !contentType.includes("multipart/form-data")) {
      resolve({
        statusCode: 400,
        headers: { "Content-Type": "text/plain" },
        body: "Content-Type must be multipart/form-data",
      });
      return;
    }

    const busboy = Busboy({ headers: { "content-type": contentType } });

    let privateKey = null;
    let secretData = null;

    busboy.on("file", (fieldname, file, filename, encoding, mimetype) => {
      let chunks = [];
      file.on("data", (chunk) => chunks.push(chunk));
      file.on("end", () => {
        const buf = Buffer.concat(chunks);
        if (fieldname === "key") privateKey = buf.toString("utf8");
        if (fieldname === "secret") secretData = buf;
      });
    });

    busboy.on("field", (fieldname, value) => {
      if (fieldname === "key") privateKey = value;
      if (fieldname === "secret") secretData = Buffer.from(value, "utf8");
    });

    busboy.on("finish", () => {
      if (!privateKey || !secretData) {
        resolve({
          statusCode: 400,
          headers: { "Content-Type": "text/plain" },
          body: 'Missing fields "key" or "secret"',
        });
        return;
      }

      let decrypted;
      try {
        const s = secretData.toString("utf8").replace(/\s+/g, "");
        const maybeBase64 = /^[A-Za-z0-9+/=]+$/.test(s);
        const ciphertext = maybeBase64 ? Buffer.from(s, "base64") : secretData;

        try {
          decrypted = privateDecrypt(
            { key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING },
            ciphertext
          );
        } catch {
          decrypted = privateDecrypt(
            { key: privateKey, padding: constants.RSA_PKCS1_PADDING },
            ciphertext
          );
        }
      } catch (err) {
        resolve({
          statusCode: 400,
          headers: { "Content-Type": "text/plain" },
          body: "Decryption failed: " + err.message,
        });
        return;
      }

      resolve({
        statusCode: 200,
        headers: { "Content-Type": "text/plain" },
        body: decrypted.toString("utf8"),
      });
    });

    const buffer = Buffer.from(event.body, event.isBase64Encoded ? "base64" : "utf8");
    busboy.end(buffer);
  });
}
