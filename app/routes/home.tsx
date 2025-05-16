import type { Route } from "./+types/home";
import { Welcome } from "../welcome/welcome";
import crypto from "node:crypto";
import dotenv from "dotenv";

export function meta({}: Route.MetaArgs) {
  return [
    { title: "New React Router App" },
    { name: "description", content: "Welcome to React Router!" },
  ];
}

export async function loader({ request }: { request: Request }) {
  dotenv.config();

  const getDeterministicSalt = (password: string): Buffer => {
    return crypto.createHash('sha256').update(password + ':salt').digest().subarray(0, 16);
  };
  const getDeterministicIV = (password: string): Buffer => {
    return crypto.createHash('sha256').update(password + ':iv').digest().subarray(0, 16);
  };
  const getKeyFromPassword = (password: string): Buffer => {
    const salt = getDeterministicSalt(password);
    return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  };

  const encrypt = (text: string, password: string): string => {
    const key = getKeyFromPassword(password);
    const iv = getDeterministicIV(password);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    return encrypted.toString('base64');
  };
  const decrypt = (data: string, password: string): string => {
    const key = getKeyFromPassword(password);
    const iv = getDeterministicIV(password);
    const encryptedText = Buffer.from(data, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
    return decrypted.toString('utf8');
  };

  return encrypt(JSON.stringify({ timestamp: Date.now(), userAgent: request.headers.get('user-agent') }), process.env.CRYPTO_PASSWORD);
}

export default function Home({ loaderData }: Route.ComponentProps) {
  return <Welcome encryptData={loaderData} />;
}
