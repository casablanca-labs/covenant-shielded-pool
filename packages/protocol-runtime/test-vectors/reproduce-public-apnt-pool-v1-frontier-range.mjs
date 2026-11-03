/** Portable public reproduction. No private publication guard or record dependency.
 * Run: node --experimental-vm-modules packages/protocol-runtime/test-vectors/reproduce-public-apnt-pool-v1-frontier-range.mjs --check
 * Dependencies come from the frozen normal project install; no scripts/install/network are run here.
 */
import fs from "node:fs";
import vm from "node:vm";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
const base = "packages/protocol-runtime/test-vectors/";
export const PUBLIC_FRONTIER_RANGE_RECIPE_PATH = base + "public-apnt-pool-v1-frontier-range-recipe.json";
export const publicReferenceSha256 = b => createHash("sha256").update(b).digest("hex");
const need = (ok, code) => { if (!ok) throw Object.assign(new Error("public-reference-" + code), { code: "public-reference-" + code }); };

export async function constructPublicFrontierRange({ sourceRoot, dependencyRoot = sourceRoot }) {
  need(typeof vm.SourceTextModule === "function", "vm-modules-required");
  sourceRoot = fs.realpathSync(sourceRoot); dependencyRoot = fs.realpathSync(dependencyRoot);
  const recipeBytes = fs.readFileSync(join(sourceRoot, PUBLIC_FRONTIER_RANGE_RECIPE_PATH)), recipe = JSON.parse(recipeBytes);
  need(recipe.schema === "public-apnt-frontier-range-recipe/1" && recipe.sources.length === 15, "recipe");
  const require = createRequire(join(dependencyRoot, "package.json"));
  const nobleRequire = createRequire(join(dependencyRoot, "packages/protocol-runtime/package.json"));
  const ts = require("typescript"); need(ts.version === recipe.typescript, "compiler");
  const noblePath = nobleRequire.resolve("@noble/curves/secp256k1");
  let nobleRoot = dirname(noblePath);
  while (!fs.existsSync(join(nobleRoot, "package.json"))) nobleRoot = dirname(nobleRoot);
  need(JSON.parse(fs.readFileSync(join(nobleRoot, "package.json"))).version === recipe.nobleCurves, "curve-version");
  const sources = new Map(recipe.sources.map(row => [join(sourceRoot, row.path), row])), modules = new Map(), ledger = [], labelReads = [];
  const auditedHash = (...args) => {
    const value = createHash(...args), update = value.update;
    value.update = function (input, ...rest) {
      if (typeof input === "string" && input.startsWith(recipe.domain + ":")) labelReads.push(input.slice(recipe.domain.length + 1));
      return Reflect.apply(update, this, [input, ...rest]);
    };
    return value;
  };
  async function moduleFor(identifier) {
    if (modules.has(identifier)) return modules.get(identifier);
    let module;
    if (["node:crypto", "node:assert/strict", "@noble/curves/secp256k1"].includes(identifier)) {
      const namespace = identifier === "node:crypto" ? { createHash: auditedHash }
        : identifier.startsWith("@") ? await import(noblePath) : await import(identifier);
      const names = Object.keys(namespace);
      module = new vm.SyntheticModule(names, function () { for (const name of names) this.setExport(name, namespace[name]); }, { identifier });
    } else {
      const row = sources.get(identifier); need(row, "source-closure");
      const stat = fs.lstatSync(identifier), bytes = fs.readFileSync(identifier);
      need(stat.isFile() && !stat.isSymbolicLink() && fs.realpathSync(identifier) === identifier
        && bytes.length === row.sizeBytes && publicReferenceSha256(bytes) === row.sha256, "source-drift");
      const ast = ts.createSourceFile(row.path, bytes.toString("utf8"), ts.ScriptTarget.Latest, true);
      function audit(node) {
        if (ts.isIdentifier(node)) need(!["process", "require", "eval", "Function", "Date", "fetch"].includes(node.text), "ambient-input");
        if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.expression)) {
          need(node.expression.text !== "Math" || node.name.text !== "random", "ambient-input");
          need(node.expression.text !== "globalThis" || node.name.text === "structuredClone", "ambient-input");
        }
        if (ts.isImportDeclaration(node)) need(ts.isStringLiteral(node.moduleSpecifier), "import");
        if (ts.isCallExpression(node)) need(node.expression.kind !== ts.SyntaxKind.ImportKeyword, "dynamic-import");
        ts.forEachChild(node, audit);
      }
      audit(ast); need(!ast.parseDiagnostics.length, "source-syntax");
      const result = ts.transpileModule(bytes.toString("utf8"), { fileName: row.path, reportDiagnostics: true,
        compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022, sourceMap: false } });
      need(!result.diagnostics.some(d => d.category === ts.DiagnosticCategory.Error), "compile");
      ledger.push({ ...row, mode: "100644" });
      module = new vm.SourceTextModule(result.outputText, { identifier, importModuleDynamically() { throw Error("public-reference-dynamic-import"); } });
    }
    modules.set(identifier, module); return module;
  }
  const entry = await moduleFor(join(sourceRoot, base + "generate-public-apnt-pool-v1-frontier-range.ts"));
  await entry.link((specifier, parent) => moduleFor(specifier.startsWith(".") ? resolve(dirname(parent.identifier), specifier).replace(/[.]js$/, ".ts") : specifier));
  await entry.evaluate();
  const inputModule = modules.get(join(sourceRoot, base + "public-apnt-pool-v1-frontier-range-inputs.ts"));
  const input = inputModule.namespace.PUBLIC_FRONTIER_RANGE_INPUTS;
  need(input.domain === recipe.domain && new Set(input.labels).size === input.labels.length, "inputs");
  const generated = entry.namespace.buildPublicFrontierRange();
  need(labelReads.every(label => input.labels.includes(label)), "undeclared-label");
  need(ledger.length === recipe.sources.length, "complete-source-closure");
  const outputs = [generated.frontier, generated.range].map((document, i) => {
    const bytes = Buffer.from(entry.namespace.serializePublicFrontierRange(document)), origins = [];
    function visit(value, path = []) {
      if (Array.isArray(value)) value.forEach((item, index) => visit(item, [...path, index]));
      else if (value && typeof value === "object") Object.entries(value).forEach(([key, item]) => visit(item, [...path, key]));
      else origins.push({ path, construction: path.includes("inbox") ? "independent-migration-encoding" : i === 1 ? "independent-range-integer-reference" : "independent-frontier-tree-reference" });
    }
    visit(document);
    return { publicPath: recipe.outputs[i], mode: "100644", bytes, sha256: publicReferenceSha256(bytes), sizeBytes: bytes.length, origins };
  });
  // Check source bytes once more after evaluation; no output may depend on a moving input.
  for (const row of recipe.sources) need(publicReferenceSha256(fs.readFileSync(join(sourceRoot, row.path))) === row.sha256, "source-drift");
  return { outputs, proof: { schema: "public-apnt-frontier-range-construction/1", recipeSha256: publicReferenceSha256(recipeBytes),
    sourceFiles: ledger.sort((a, b) => a.path.localeCompare(b.path)), domain: input.domain, inputManifest: input,
    actualLabelReads: [...new Set(labelReads)].sort(), actualLabelReadCount: labelReads.length,
    node: process.version, compiler: ts.version, privateInputs: 0, oldVectorReads: 0, mainGenerationCalls: 0,
    outputs: outputs.map(({ bytes, origins, ...row }) => ({ ...row, fieldCount: origins.length })),
    generator: base + "generate-public-apnt-pool-v1-frontier-range.ts" } };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../.."), result = await constructPublicFrontierRange({ sourceRoot });
  need(process.argv.length === 3 && process.argv[2] === "--check", "usage-check");
  for (const output of result.outputs) need(fs.readFileSync(join(sourceRoot, output.publicPath)).equals(output.bytes), "output-drift");
  console.log(JSON.stringify(result.proof.outputs));
}
