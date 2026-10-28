const publicBaseUrl = Deno.env.get("PUBLIC_BASE_URL");

if (!publicBaseUrl) {
  throw new Error("PUBLIC_BASE_URL is required");
}

const parsedUrl = new URL(publicBaseUrl);

if (parsedUrl.protocol !== "https:" && parsedUrl.hostname !== "localhost") {
  throw new Error("PUBLIC_BASE_URL must use HTTPS");
}

export const SERVER_ORIGIN = parsedUrl.origin;
export const SERVER_DOMAIN = parsedUrl.host;
