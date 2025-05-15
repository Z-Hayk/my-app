import type { Route } from "./+types/home";
import { Welcome } from "../welcome/welcome";
import crypto from "node:crypto";
import dotenv from "dotenv";

const getKeyFromPassword = (password: string, salt: Buffer): Buffer => {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
};
const encrypt = (text: string, password: string): string => {
  const iv = crypto.randomBytes(16);
  const salt = crypto.randomBytes(16);
  const key = getKeyFromPassword(password, salt);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return Buffer.concat([salt, iv, encrypted]).toString('base64');
};
const decrypt = (data: string, password: string): string => {
  const bData = Buffer.from(data, 'base64');
  const salt = Buffer.from(bData.subarray(0, 16));
  const iv = Buffer.from(bData.subarray(16, 32));
  const encryptedText = Buffer.from(bData.subarray(32));
  const key = getKeyFromPassword(password, salt);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
  return decrypted.toString('utf8');
};

export function meta({}: Route.MetaArgs) {
  return [
    { title: "New React Router App" },
    { name: "description", content: "Welcome to React Router!" },
  ];
}

export async function loader() {
  dotenv.config();
  return encrypt(JSON.stringify({ visitorId: process.env.CRYPTO_PASSWORD }), process.env.CRYPTO_PASSWORD);
}

export default function Home({ loaderData }: Route.ComponentProps) {
  return <Welcome encryptData={loaderData} />;
}
