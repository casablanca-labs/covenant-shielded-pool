import * as libauth from "@bitauth/libauth";

/** Only the libauth operations needed by the self-contained instruction-set correction. */
export type BchnVmLibauth = Pick<typeof libauth,
  "createInstructionSetBch2026" | "OpcodesBchSpec" | "executionIsActive">;

/**
 * BCH 2026 accounting with BCHN v29's OP_DEFINE body-byte charge (ENG-766, ARCH-353).
 * libauth 3.1.0-next.8 omits this TallyPushOp; the VM's own `every` hook applies
 * the cost limit after the charge, in standard and consensus modes.
 *
 * Keep this function self-contained: the gated verifier driver inlines its
 * compiled source into a scratch tree with its own libauth namespace.
 * This corrects one accounting difference; it is local VM evidence only.
 */
export function bchnInstructionSet(lib: BchnVmLibauth, standard: boolean): ReturnType<typeof libauth.createInstructionSetBch2026> {
  const base = lib.createInstructionSetBch2026(standard);
  const opDefine = lib.OpcodesBchSpec.OP_DEFINE;
  const define = base.operations[opDefine]!;
  return {
    ...base,
    operations: {
      ...base.operations,
      [opDefine]: (state) => {
        // <body> <identifier> OP_DEFINE: inactive branches and failed definitions add no charge.
        const body = lib.executionIsActive(state) && state.stack.length >= 2 ? state.stack[state.stack.length - 2]! : null;
        const next = define(state);
        if (body !== null && next.error === undefined) next.metrics.stackPushedBytes += body.length;
        return next;
      },
    },
  };
}

/** libauth's BCH 2026 VM with BCHN v29's OP_DEFINE charge; standard accounting by default. */
export const createVirtualMachineBch2026Bchn = (standard = true) =>
  libauth.createVirtualMachine(bchnInstructionSet(libauth, standard));
