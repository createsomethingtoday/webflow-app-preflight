/**
 * Webflow-owned static hosts a published site needs in order to render:
 * compiled CSS, webflow.js, images and fonts from the asset CDN, plus the
 * jQuery CDN Webflow sites load. The runtime sandbox allows them so the page
 * under observation behaves as it does for a visitor. They are read-only CDNs
 * partner code cannot read anything back through, so allowing them does not
 * widen what a partner runtime can reach; its own host was always allowed.
 *
 * The runner keeps its own copy of this list and refuses any contract that
 * names a host outside it. A runner test pins the two copies to each other.
 */
export const WEBFLOW_PLATFORM_ASSET_HOSTS = [
  'cdn.prod.website-files.com',
  'assets.website-files.com',
  'assets-global.website-files.com',
  'uploads-ssl.webflow.com',
  'd3e54v103j8qbb.cloudfront.net'
] as const;
