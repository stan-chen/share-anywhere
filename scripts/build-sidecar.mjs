import fs from "node:fs";
import path from "node:path";
import { execa } from "execa";

const root_dir = path.dirname(path.dirname(process.argv[1]));
const src_tauri_dir = path.join(root_dir, "src-tauri");

async function main() {
  await execa(
    "cargo",
    ["build", "-p", "clipboard", "--bin", "clip-cli", "--release", "--features", "command-line"],
    {
      stdout: "inherit",
      stderr: "inherit",
      cwd: src_tauri_dir,
      verbose: true
    }
  );
  const rustInfo = (await execa("rustc", ["-vV"])).stdout;
  const targetTriple = /host: (\S+)/g.exec(rustInfo)[1];
  if (!targetTriple) {
    console.error("Failed to determine platform target triple");
  }
  fs.mkdirSync(`${src_tauri_dir}/binaries`, {
      recursive: true
  });
  fs.renameSync(
    `${src_tauri_dir}/target/release/clip-cli`,
    `${src_tauri_dir}/binaries/clip-cli-${targetTriple}`
  );
}

main().catch((e) => {
  throw e;
});
