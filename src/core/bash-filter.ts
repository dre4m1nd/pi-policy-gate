import type { BashPermissions, PermissionState } from "./types.js";
import {
  findCompiledWildcardMatch,
  type CompiledWildcardPattern,
} from "./wildcard-matcher.js";
import { compileCommandPatterns } from "./bash-command.js";

type CompiledPattern = CompiledWildcardPattern<PermissionState>;

type BashPermissionSource = BashPermissions | readonly CompiledPattern[];

function isCompiledPatternList(value: BashPermissionSource): value is readonly CompiledPattern[] {
  return Array.isArray(value);
}

export interface BashPermissionCheck {
  state: PermissionState;
  matchedPattern?: string;
  command: string;
}

export class BashFilter {
  private readonly compiledPatterns: CompiledPattern[];

  constructor(
    permissions: BashPermissionSource,
    private readonly defaultState: PermissionState,
  ) {
    this.compiledPatterns = isCompiledPatternList(permissions)
      ? [...permissions]
      : compileCommandPatterns(permissions);
  }

  check(command: string): BashPermissionCheck {
    const match = findCompiledWildcardMatch(this.compiledPatterns, command);
    if (match) {
      return {
        state: match.state,
        matchedPattern: match.matchedPattern,
        command,
      };
    }

    return {
      state: this.defaultState,
      command,
    };
  }
}
