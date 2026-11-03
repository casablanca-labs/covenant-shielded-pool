// Reviewed installation configuration, anchored to the native account, not HOME or PATH.
import { userInfo } from "node:os";
import { join } from "node:path";
export const PRIVATE_RUNNER_NODE_RELATIVE = ".nvm/versions/node/v22.22.3/bin/node";
export const PRIVATE_RUNNER_NODE_VERSION = "v22.22.3";
export const PRIVATE_RUNNER_NODE = join(userInfo().homedir, PRIVATE_RUNNER_NODE_RELATIVE);
export const PRIVATE_RUNNER_GO = "/opt/homebrew/bin/go";
