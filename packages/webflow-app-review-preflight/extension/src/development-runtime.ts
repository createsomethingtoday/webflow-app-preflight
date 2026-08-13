function isLocalDevelopmentHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1";
}

export function developmentApiBase(hostname: string): string | null {
  return isLocalDevelopmentHost(hostname) ? "http://localhost:8787" : null;
}

export function developmentIdToken(hostname: string): string | null {
  return isLocalDevelopmentHost(hostname) ? "test-token" : null;
}
