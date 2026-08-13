// Production builds resolve the development-runtime import to this module. Keeping
// the boundary at module resolution prevents development credentials and hosts from
// entering either the executable bundle or its reviewer-readable source map.
export function developmentApiBase(_hostname: string): null {
  return null;
}

export function developmentIdToken(_hostname: string): null {
  return null;
}
